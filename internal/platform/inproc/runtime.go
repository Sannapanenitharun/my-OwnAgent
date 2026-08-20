package inproc

import (
	"context"
	"fmt"
	"sync"

	"github.com/obsagent/observability-agent/internal/platform"
)

// CapabilityRuntime is an in-process platform.CapabilityRuntime.
//
// Admission is gated on an explicit grant set: a capability may only register
// with permissions that have been granted to it, and Authorize denies anything
// not granted. This mirrors the fail-closed posture the real IAM must have, so
// that modules are exercised against denial paths from Stage 1 rather than
// discovering them at integration time.
type CapabilityRuntime struct {
	mu       sync.Mutex
	grants   map[string]map[platform.Permission]bool
	active   map[string]bool
	released map[string]int
}

// NewCapabilityRuntime returns a runtime with no grants. Every registration
// that requires a permission will be denied until Grant is called.
func NewCapabilityRuntime() *CapabilityRuntime {
	return &CapabilityRuntime{
		grants:   make(map[string]map[platform.Permission]bool),
		active:   make(map[string]bool),
		released: make(map[string]int),
	}
}

// Grant authorizes a capability to hold the given permissions.
func (r *CapabilityRuntime) Grant(capabilityID string, perms ...platform.Permission) {
	r.mu.Lock()
	defer r.mu.Unlock()
	set, ok := r.grants[capabilityID]
	if !ok {
		set = make(map[platform.Permission]bool)
		r.grants[capabilityID] = set
	}
	for _, p := range perms {
		set[p] = true
	}
}

// Revoke removes a permission from a capability.
func (r *CapabilityRuntime) Revoke(capabilityID string, perm platform.Permission) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.grants[capabilityID], perm)
}

func (r *CapabilityRuntime) Register(ctx context.Context, desc platform.CapabilityDescriptor) (platform.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if desc.ID == "" {
		return nil, fmt.Errorf("inproc: capability descriptor missing ID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active[desc.ID] {
		return nil, fmt.Errorf("inproc: capability %q already registered", desc.ID)
	}
	granted := r.grants[desc.ID]
	for _, p := range desc.Permissions {
		if !granted[p] {
			return nil, fmt.Errorf("%w: capability %q requires %q", platform.ErrDenied, desc.ID, p)
		}
	}
	r.active[desc.ID] = true
	return &lease{r: r, id: desc.ID}, nil
}

func (r *CapabilityRuntime) Authorize(ctx context.Context, capabilityID string, perm platform.Permission) error {
	if err := ctx.Err(); err != nil {
		// Fail closed: an expired context denies rather than allows.
		return fmt.Errorf("%w: %v", platform.ErrDenied, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active[capabilityID] {
		return fmt.Errorf("%w: capability %q is not registered", platform.ErrDenied, capabilityID)
	}
	if !r.grants[capabilityID][perm] {
		return fmt.Errorf("%w: capability %q lacks %q", platform.ErrDenied, capabilityID, perm)
	}
	return nil
}

// ActiveCount reports how many capabilities currently hold a lease.
func (r *CapabilityRuntime) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

// ReleaseCount reports how many times a capability's lease was released.
func (r *CapabilityRuntime) ReleaseCount(capabilityID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.released[capabilityID]
}

type lease struct {
	r    *CapabilityRuntime
	id   string
	once sync.Once
}

func (l *lease) Release(context.Context) error {
	l.once.Do(func() {
		l.r.mu.Lock()
		defer l.r.mu.Unlock()
		delete(l.r.active, l.id)
		l.r.released[l.id]++
	})
	return nil
}

var _ platform.CapabilityRuntime = (*CapabilityRuntime)(nil)
