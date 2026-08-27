package native

import (
	"strings"
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
)

func entityEvent(name string, kv ...string) platform.Event {
	attrs := make([]platform.Attr, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		attrs = append(attrs, platform.A(kv[i], kv[i+1]))
	}
	return platform.Event{Name: name, Attrs: attrs}
}

func kindsOf(evs []platform.Event) map[string]int {
	out := map[string]int{}
	for _, ev := range evs {
		for _, a := range ev.Attrs {
			if a.Key == "entity.kind" {
				out[a.Value]++
			}
		}
	}
	return out
}

// TestStableEntitiesSurviveChurn is the regression test for the defect this
// file exists to fix. Discovery announces a filesystem once and then never
// again, while endpoints churn every cycle. Reading the inventory straight out
// of the shared FIFO event ring meant the mounts, the host record and the cloud
// instance were evicted within a minute and never shipped again.
func TestStableEntitiesSurviveChurn(t *testing.T) {
	e := New(nil, Config{})

	// Cycle one: the host announces everything it has.
	first := []platform.Event{
		entityEvent("discovery.entity.discovered", "entity.kind", "host", "hostname", "teleport"),
		entityEvent("discovery.entity.discovered", "entity.kind", "cloud_instance", "provider", "aws"),
		entityEvent("discovery.entity.discovered", "entity.kind", "filesystem", "mountpoint", "/"),
		entityEvent("discovery.entity.discovered", "entity.kind", "filesystem", "mountpoint", "/boot"),
	}
	if got := len(e.foldInventory(first)); got != 4 {
		t.Fatalf("first cycle shipped %d entities, want 4", got)
	}

	// Later cycles: the ring holds only recent endpoint churn. The stable
	// entities are no longer in it, and that must not mean they are gone.
	churn := make([]platform.Event, 0, 200)
	for i := 0; i < 200; i++ {
		churn = append(churn, entityEvent("discovery.entity.discovered",
			"entity.kind", "network_endpoint", "protocol", "tcp",
			"address", "10.0.0.1", "port", string(rune('a'+i%26))+"000"))
	}
	got := kindsOf(e.foldInventory(churn))

	if got["filesystem"] != 2 {
		t.Errorf("filesystems = %d, want 2 -- they were evicted by churn", got["filesystem"])
	}
	if got["host"] != 1 || got["cloud_instance"] != 1 {
		t.Errorf("host=%d cloud_instance=%d, want 1 each", got["host"], got["cloud_instance"])
	}
}

func TestRemovedEntityStopsBeingReported(t *testing.T) {
	e := New(nil, Config{})
	e.foldInventory([]platform.Event{
		entityEvent("discovery.entity.discovered", "entity.kind", "container", "container_id", "abc"),
		entityEvent("discovery.entity.discovered", "entity.kind", "container", "container_id", "def"),
	})
	out := e.foldInventory([]platform.Event{
		entityEvent("discovery.entity.removed", "entity.kind", "container", "container_id", "abc"),
	})
	if len(out) != 1 {
		t.Fatalf("inventory = %d entities, want 1 after a removal", len(out))
	}
	if k := inventoryKey(out[0]); k != "container|def" {
		t.Errorf("surviving entity = %q, want the one that was not removed", k)
	}
}

func TestRepeatedAnnouncementIsAnUpdateNotADuplicate(t *testing.T) {
	// The agent re-announces its retained set. A repeat must update the entity
	// in place; folding it as new is how 21 containers became 42.
	e := New(nil, Config{})
	for i := 0; i < 5; i++ {
		e.foldInventory([]platform.Event{
			entityEvent("discovery.entity.discovered",
				"entity.kind", "container", "container_id", "abc", "status", "Up 3 days"),
		})
	}
	out := e.foldInventory(nil)
	if len(out) != 1 {
		t.Fatalf("inventory = %d, want 1", len(out))
	}
}

func TestEnrichmentRenamesRatherThanDuplicating(t *testing.T) {
	// Turning on docker.socket renames a container from its ID to its real
	// name. The key must not contain the name, or that reads as a new
	// container.
	e := New(nil, Config{})
	id := "197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"
	e.foldInventory([]platform.Event{
		entityEvent("discovery.entity.discovered",
			"entity.kind", "container", "container_id", id, "name", id),
	})
	out := e.foldInventory([]platform.Event{
		entityEvent("discovery.entity.changed",
			"entity.kind", "container", "container_id", id, "name", "grafana"),
	})
	if len(out) != 1 {
		t.Fatalf("inventory = %d, want 1: enrichment renames, it does not duplicate", len(out))
	}
}

func TestResolvedEntityIDIsPreferredAsTheKey(t *testing.T) {
	// When the platform named the entity, that name is what the rest of the
	// agent agrees on, so two events carrying the same target id are the same
	// entity even if their other attributes differ.
	e := New(nil, Config{})
	e.foldInventory([]platform.Event{
		entityEvent("discovery.entity.discovered",
			"entity.kind", "filesystem", "entity.target.id", "fs-1", "mountpoint", "/mnt/a"),
		entityEvent("discovery.entity.changed",
			"entity.kind", "filesystem", "entity.target.id", "fs-1", "mountpoint", "/mnt/b"),
	})
	if out := e.foldInventory(nil); len(out) != 1 {
		t.Errorf("inventory = %d, want 1 entity under one target id", len(out))
	}
}

func TestInventoryIsBoundedAndTheOverflowIsCounted(t *testing.T) {
	// A host churning through short-lived entities must not become unbounded
	// memory, and a truncated inventory must not be silent -- it looks exactly
	// like a smaller host.
	e := New(nil, Config{})
	evs := make([]platform.Event, 0, maxInventoryEntities+100)
	for i := 0; i < maxInventoryEntities+100; i++ {
		evs = append(evs, entityEvent("discovery.entity.discovered",
			"entity.kind", "process", "name", "p", "pid", strings.Repeat("x", 1)+itoa(i)))
	}
	out := e.foldInventory(evs)
	if len(out) != maxInventoryEntities {
		t.Errorf("inventory = %d, want the cap of %d", len(out), maxInventoryEntities)
	}
	held, dropped := e.InventorySize()
	if held != maxInventoryEntities {
		t.Errorf("held = %d, want %d", held, maxInventoryEntities)
	}
	if dropped != 100 {
		t.Errorf("dropped = %d, want 100 counted overflows", dropped)
	}
}

func TestNonEntityEventsAreIgnored(t *testing.T) {
	// The event buffer is shared with every other module. Only entity events
	// are inventory.
	e := New(nil, Config{})
	out := e.foldInventory([]platform.Event{
		entityEvent("discovery.snapshot", "entity_count", "12"),
		entityEvent("discovery.relationship.discovered", "relation", "runs_service"),
		entityEvent("agent.module.started", "module", "logs"),
		entityEvent("discovery.entity.discovered", "entity.kind", "host", "hostname", "h"),
	})
	if len(out) != 1 {
		t.Fatalf("inventory = %d, want only the entity event", len(out))
	}
}

func TestShippedOrderIsStableAcrossCycles(t *testing.T) {
	// An inventory that reshuffles every cycle makes a diff of two payloads
	// useless, and map iteration order in Go is deliberately random.
	e := New(nil, Config{})
	evs := []platform.Event{
		entityEvent("discovery.entity.discovered", "entity.kind", "filesystem", "mountpoint", "/"),
		entityEvent("discovery.entity.discovered", "entity.kind", "filesystem", "mountpoint", "/boot"),
		entityEvent("discovery.entity.discovered", "entity.kind", "filesystem", "mountpoint", "/var"),
		entityEvent("discovery.entity.discovered", "entity.kind", "host", "hostname", "h"),
	}
	e.foldInventory(evs)
	want := keysOf(e.foldInventory(nil))
	for i := 0; i < 20; i++ {
		if got := keysOf(e.foldInventory(nil)); got != want {
			t.Fatalf("order changed between cycles:\n %s\n %s", want, got)
		}
	}
}

func keysOf(evs []platform.Event) string {
	parts := make([]string, 0, len(evs))
	for _, ev := range evs {
		parts = append(parts, inventoryKey(ev))
	}
	return strings.Join(parts, ",")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
