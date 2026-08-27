package discovery

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/config"
)

// dockerStub serves a canned /containers/json over a real TCP listener. The
// client dials through an injected dialer, so these tests need no Docker
// daemon and no unix socket, and therefore run on every platform CI covers.
func dockerStub(t *testing.T, handler http.HandlerFunc) *dockerClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	return &dockerClient{
		dial: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
		timeout: 2 * time.Second,
	}
}

const twoContainers = `[
  {"Id":"197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381",
   "Names":["/grafana"],"Image":"grafana/grafana:12.4.0","State":"running",
   "Status":"Up 3 days","Created":1756000000,
   "Ports":[{"IP":"0.0.0.0","PrivatePort":3000,"PublicPort":3000,"Type":"tcp"}]},
  {"Id":"48434aebd534f81846b6b70fd144ca31b1a155c0a15121df895cdb2bdc97d944",
   "Names":["/prometheus"],"Image":"prom/prometheus:v3.5.0","State":"running",
   "Status":"Up 3 days","Created":1756000001,"Ports":[]}
]`

func TestEnrichContainersFillsNameImageAndState(t *testing.T) {
	cli := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		// The agent must only ever read from this socket.
		if r.Method != http.MethodGet {
			t.Errorf("method = %s; the docker client must never write", r.Method)
		}
		_, _ = w.Write([]byte(twoContainers))
	})

	facts := []ContainerFacts{
		{ID: "197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381", Runtime: ContainerRuntimeDocker},
		{ID: "48434aebd534f81846b6b70fd144ca31b1a155c0a15121df895cdb2bdc97d944", Runtime: ContainerRuntimeDocker},
	}
	got := enrichContainers(context.Background(), cli, facts)

	if got[0].Name != "grafana" {
		t.Errorf("name = %q, want grafana (leading slash stripped)", got[0].Name)
	}
	if got[0].Image != "grafana/grafana:12.4.0" {
		t.Errorf("image = %q", got[0].Image)
	}
	if got[0].State != "running" || got[0].Status != "Up 3 days" {
		t.Errorf("state=%q status=%q", got[0].State, got[0].Status)
	}
	if got[0].Ports != "3000->3000/tcp" {
		t.Errorf("ports = %q", got[0].Ports)
	}
	if got[0].CreatedUnix != 1756000000 {
		t.Errorf("created = %d", got[0].CreatedUnix)
	}
	if got[1].Name != "prometheus" {
		t.Errorf("second name = %q", got[1].Name)
	}
	// A container publishing nothing must render no ports, not "0->0/tcp".
	if got[1].Ports != "" {
		t.Errorf("ports = %q, want empty for an unpublished container", got[1].Ports)
	}
}

func TestEnrichMatchesTruncatedCgroupID(t *testing.T) {
	// cgroup paths sometimes carry a shortened ID; the daemon always reports
	// the full one.
	cli := dockerStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(twoContainers))
	})
	facts := []ContainerFacts{{ID: "197a67528722", Runtime: ContainerRuntimeDocker}}
	got := enrichContainers(context.Background(), cli, facts)
	if got[0].Name != "grafana" {
		t.Errorf("name = %q, want grafana matched by ID prefix", got[0].Name)
	}
}

func TestEnrichNeverAddsContainersTheHostIsNotRunning(t *testing.T) {
	// The daemon knows about containers this host has no process for. An
	// entity must be something observed here, so the list must not grow.
	cli := dockerStub(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(twoContainers))
	})
	facts := []ContainerFacts{{ID: "197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"}}
	got := enrichContainers(context.Background(), cli, facts)
	if len(got) != 1 {
		t.Errorf("facts grew to %d; enrichment must describe, never discover", len(got))
	}
}

func TestEnrichIsNeverFatal(t *testing.T) {
	facts := []ContainerFacts{{ID: "abc123def456", Runtime: ContainerRuntimeDocker}}

	cases := map[string]http.HandlerFunc{
		"permission denied": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
		"garbage body": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json at all"))
		},
		"empty list": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[]`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			in := append([]ContainerFacts(nil), facts...)
			got := enrichContainers(context.Background(), dockerStub(t, h), in)
			if len(got) != 1 || got[0].ID != "abc123def456" {
				t.Fatalf("cgroup-derived facts lost: %+v", got)
			}
			if got[0].Name != "" {
				t.Errorf("name = %q, want empty when the daemon cannot answer", got[0].Name)
			}
		})
	}
}

func TestEnrichWithNoClientIsAPassthrough(t *testing.T) {
	// The default: no socket configured, so no enrichment and no attempt.
	facts := []ContainerFacts{{ID: "abc", Runtime: ContainerRuntimeDocker}}
	got := enrichContainers(context.Background(), nil, facts)
	if len(got) != 1 || got[0].Name != "" {
		t.Errorf("unexpected change with no client: %+v", got)
	}
}

func TestDockerClientIsOffUnlessASocketIsConfigured(t *testing.T) {
	// Enrichment is root-equivalent, so it must never switch itself on.
	if c := newDockerFrom(Settings{}); c != nil {
		t.Error("a client was built with no docker.socket configured")
	}
	if c := newDockerFrom(Settings{DockerSocket: "   "}); c != nil {
		t.Error("whitespace must not count as a configured socket")
	}
	if c := newDockerFrom(Settings{DockerSocket: "/var/run/docker.sock"}); c == nil {
		t.Error("no client built despite a configured socket")
	}
}

func TestDockerSocketSettingParses(t *testing.T) {
	s, err := ParseSettings(config.ModuleConfig{Settings: map[string]string{"docker.socket": " /var/run/docker.sock "}})
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if s.DockerSocket != "/var/run/docker.sock" {
		t.Errorf("DockerSocket = %q", s.DockerSocket)
	}
	if def, _ := ParseSettings(config.ModuleConfig{}); def.DockerSocket != "" {
		t.Errorf("default DockerSocket = %q, want empty (off)", def.DockerSocket)
	}
}

func TestDockerSlowDaemonDoesNotBlockCollection(t *testing.T) {
	// A hung daemon must not stall a collection cycle.
	cli := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	cli.timeout = 150 * time.Millisecond

	facts := []ContainerFacts{{ID: "abc123def456"}}
	start := time.Now()
	got := enrichContainers(context.Background(), cli, facts)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("enrichment took %v; it must be bounded by its timeout", elapsed)
	}
	if len(got) != 1 {
		t.Error("facts lost on timeout")
	}
}

func TestDockerRequestIsUnversioned(t *testing.T) {
	// Pinning an API version is a compatibility trap: Docker removes support
	// for versions below its MinAPIVersion, so a pinned v1.24 is rejected by
	// Docker 29 with "client version 1.24 is too old". The unversioned path
	// negotiates to whatever the daemon speaks.
	var gotPath string
	cli := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(twoContainers))
	})
	enrichContainers(context.Background(), cli, []ContainerFacts{{ID: "197a67528722"}})

	if gotPath != "/containers/json" {
		t.Errorf("path = %q, want /containers/json with no version prefix", gotPath)
	}
	if strings.Contains(gotPath, "/v1.") {
		t.Errorf("path %q pins an API version; a modern daemon will reject it", gotPath)
	}
}

func TestDockerRejectionByVersionIsNotFatal(t *testing.T) {
	// Whatever the daemon objects to, the cgroup-derived facts must survive.
	cli := dockerStub(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"client version 1.24 is too old. Minimum supported API version is 1.40"}`))
	})
	got := enrichContainers(context.Background(), cli, []ContainerFacts{{ID: "abc123def456", Runtime: ContainerRuntimeDocker}})
	if len(got) != 1 || got[0].ID != "abc123def456" {
		t.Fatalf("facts lost on a version rejection: %+v", got)
	}
}
