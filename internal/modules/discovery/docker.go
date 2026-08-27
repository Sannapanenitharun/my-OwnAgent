package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Container names, images and state are not derivable from cgroups: a cgroup
// path carries an ID and nothing else. They live in the runtime's own API, so
// enriching a container entity means asking Docker.
//
// This is deliberately opt-in (discovery setting "docker.socket", empty by
// default). Read access to the Docker socket is root-equivalent on the host --
// the same socket that answers GET /containers/json also accepts requests that
// start a privileged container -- so the agent must never assume that
// authority just because the socket happens to be present. Every call this
// client makes is a GET, and it never writes.
//
// Failure is never fatal. If the socket is absent, unreadable, or slow, the
// container entities keep the ID-only facts the cgroup walk produced.

// dockerMaxBody caps the response. A host with thousands of containers would
// otherwise hand the agent an unbounded body to parse.
const dockerMaxBody = 8 << 20

// dockerClient talks to a Docker Engine API over a socket. dial is injected so
// the client can be tested without a Docker daemon, and so a non-Unix platform
// can supply its own transport.
type dockerClient struct {
	dial    func(ctx context.Context) (net.Conn, error)
	timeout time.Duration
}

// newDockerClient returns a client for a unix socket path.
func newDockerClient(socket string, timeout time.Duration) *dockerClient {
	return &dockerClient{
		dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		timeout: timeout,
	}
}

// dockerContainer is the subset of GET /containers/json this agent reads.
// Anything not needed to identify or describe a container is left unparsed.
type dockerContainer struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
	// Created is Unix seconds.
	Created int64 `json:"Created"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	Labels map[string]string `json:"Labels"`
}

// list returns the running containers the daemon reports.
func (c *dockerClient) list(ctx context.Context) ([]dockerContainer, error) {
	if c == nil || c.dial == nil {
		return nil, errors.New("docker: no client")
	}
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return c.dial(ctx)
		},
		// One request per collection cycle; a pool would hold a socket open to
		// a privileged endpoint for no benefit.
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	// Unversioned on purpose. Pinning an API version does not buy compatibility
	// with older daemons: Docker REMOVES support for versions below its
	// MinAPIVersion, so a pinned v1.24 is rejected outright by Docker 29 with
	// "client version 1.24 is too old". The unversioned path negotiates to
	// whatever the daemon speaks, and the handful of fields read here have been
	// present since well before any daemon still in service.
	//
	// The host is ignored for a unix socket but must be syntactically present.
	url := "http://docker/containers/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, dockerMaxBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: unexpected status %d", resp.StatusCode)
	}

	var out []dockerContainer
	if err := json.NewDecoder(io.LimitReader(resp.Body, dockerMaxBody)).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// enrichContainers fills in what the cgroup walk cannot know. Facts already
// derived from cgroups win: an ID or Kubernetes reference read from the
// filesystem is evidence about this host, while the daemon's view is a
// description of it.
//
// Containers the daemon reports but no process on this host is running are not
// added. The discovery contract is that an entity is something observed here,
// and a created-but-not-running container has no presence on the host.
func enrichContainers(ctx context.Context, cli *dockerClient, facts []ContainerFacts) []ContainerFacts {
	if cli == nil || len(facts) == 0 {
		return facts
	}
	list, err := cli.list(ctx)
	if err != nil || len(list) == 0 {
		return facts
	}

	byID := make(map[string]*dockerContainer, len(list))
	for i := range list {
		id := strings.TrimSpace(list[i].ID)
		if id == "" {
			continue
		}
		byID[id] = &list[i]
	}

	for i := range facts {
		id := strings.TrimSpace(facts[i].ID)
		if id == "" {
			continue
		}
		d := byID[id]
		if d == nil {
			// cgroup paths sometimes carry a truncated ID. Fall back to a
			// prefix match, which is unambiguous at 12 hex characters.
			if len(id) >= 12 {
				for fullID, cand := range byID {
					if strings.HasPrefix(fullID, id) {
						d = cand
						break
					}
				}
			}
			if d == nil {
				continue
			}
		}
		facts[i].Name = dockerName(d.Names)
		facts[i].Image = strings.TrimSpace(d.Image)
		facts[i].State = strings.TrimSpace(d.State)
		facts[i].Status = strings.TrimSpace(d.Status)
		facts[i].CreatedUnix = d.Created
		facts[i].Ports = dockerPorts(d)
	}
	return facts
}

// dockerName picks the container's display name. Docker returns names with a
// leading slash, and a container attached to another's network stack can carry
// several; the first is the container's own.
func dockerName(names []string) string {
	for _, n := range names {
		n = strings.TrimSpace(strings.TrimPrefix(n, "/"))
		if n != "" {
			return n
		}
	}
	return ""
}

// dockerPorts renders the published port mappings compactly. Unpublished ports
// are omitted: an exposed-but-unmapped port tells an operator nothing about
// what is reachable.
func dockerPorts(d *dockerContainer) string {
	if d == nil || len(d.Ports) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	for _, p := range d.Ports {
		if p.PublicPort == 0 {
			continue
		}
		proto := p.Type
		if proto == "" {
			proto = "tcp"
		}
		s := fmt.Sprintf("%d->%d/%s", p.PublicPort, p.PrivatePort, proto)
		if seen[s] {
			continue
		}
		seen[s] = true
		parts = append(parts, s)
		// A container can publish a very large range; the detail line is a
		// summary, not an inventory of every port.
		if len(parts) >= 8 {
			parts = append(parts, "...")
			break
		}
	}
	return strings.Join(parts, " ")
}

// newDockerFrom returns a client only when the operator configured a socket.
// An unset socket means enrichment is off, which is the default.
func newDockerFrom(s Settings) *dockerClient {
	socket := strings.TrimSpace(s.DockerSocket)
	if socket == "" {
		return nil
	}
	timeout := s.CollectionTimeout
	if timeout <= 0 || timeout > 5*time.Second {
		timeout = 2 * time.Second
	}
	return newDockerClient(socket, timeout)
}
