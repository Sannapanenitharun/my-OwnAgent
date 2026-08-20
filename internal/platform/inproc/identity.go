package inproc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/obsagent/observability-agent/internal/platform"
)

// Identity is a static platform.Identity backed by explicitly supplied values.
//
// Any field left empty resolves to platform.ErrUnresolved. This is deliberate
// and load-bearing: entity identity is owned by the platform Discovery Runtime
// and Digital Twin, so an adapter that cannot obtain an identifier must say so
// and let the caller emit an unresolved diagnostic. It must never derive a
// plausible-looking identifier of its own, because a locally-invented entity ID
// silently forks the entity graph.
type Identity struct {
	Agent  string
	Tenant string
	Host   string
}

// NewIdentity returns a static Identity.
func NewIdentity(agent, tenant, host string) *Identity {
	return &Identity{Agent: agent, Tenant: tenant, Host: host}
}

func (i *Identity) AgentID(context.Context) (string, error) {
	return resolve("agent_id", i.Agent)
}

func (i *Identity) TenantID(context.Context) (string, error) {
	return resolve("tenant_id", i.Tenant)
}

func (i *Identity) HostID(context.Context) (string, error) {
	return resolve("host_id", i.Host)
}

func resolve(field, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%w: %s", platform.ErrUnresolved, field)
	}
	return value, nil
}

// ResolveEntity implements platform.EntityResolver.
//
// Note carefully who is allowed to do this. Assigning an EntityID from a natural
// key is the Discovery Runtime's job, and this adapter is the in-process
// stand-in for it — so here, and only here, an identifier may be derived. A
// COLLECTOR doing the same thing would be the fork this design exists to
// prevent, which is why the derivation lives behind the port rather than in a
// helper any module could reach for.
//
// The derivation is a truncated SHA-256 over the kind, the parent and the
// ordered natural key. Determinism is the whole point: the same process instance
// observed by two collections, or after an agent restart, must resolve to the
// same identifier.
//
// Resolution requires a resolved host: a process entity that cannot be placed
// under its host has nowhere to live in the entity graph, so an unresolved host
// yields ErrUnresolved rather than an orphan.
func (i *Identity) ResolveEntity(_ context.Context, ref platform.EntityRef) (string, error) {
	if i.Host == "" {
		return "", fmt.Errorf("%w: no host entity to anchor a %s entity to",
			platform.ErrUnresolved, ref.Kind)
	}
	if ref.Kind == "" || len(ref.Keys) == 0 {
		return "", fmt.Errorf("%w: entity reference has no kind or no natural key",
			platform.ErrUnresolved)
	}

	h := sha256.New()
	io.WriteString(h, string(ref.Kind))
	h.Write([]byte{0})
	io.WriteString(h, ref.Parent)
	for _, a := range ref.Keys {
		h.Write([]byte{0})
		io.WriteString(h, a.Key)
		h.Write([]byte{'='})
		io.WriteString(h, a.Value)
	}
	return string(ref.Kind) + "-" + hex.EncodeToString(h.Sum(nil)[:12]), nil
}

var (
	_ platform.Identity       = (*Identity)(nil)
	_ platform.EntityResolver = (*Identity)(nil)
)
