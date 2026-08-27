package native

import (
	"sort"
	"strings"

	"github.com/obsagent/observability-agent/internal/platform"
)

// The inventory is a SET, not a stream, and this file is what makes the
// exporter treat it as one.
//
// Entity events reach the exporter through the telemetry event buffer, which is
// a fixed-size FIFO ring shared by every module. That is the right shape for
// events -- a log of things that happened, oldest discarded first -- and the
// wrong shape for an inventory. Discovery emits an entity event when something
// CHANGES, so a filesystem is announced once at startup and then never again,
// while network endpoints churn every cycle. Scraping the ring therefore
// shipped whatever had happened recently rather than what exists: on a host
// with five hundred entities the mounts, the host record and the cloud instance
// were pushed out by endpoint churn within the first minute and never appeared
// in the fleet view again, and the only visible symptom was an inventory that
// was quietly missing five of the twelve kinds the agent collects.
//
// Folding those events into a keyed table here fixes that. An entity stays
// until it is reported removed, a repeated announcement is an update rather
// than a duplicate, and what ships each cycle is the current set.

// maxInventoryEntities bounds the table. It matches the discovery module's own
// MaxEntities default: the exporter should be able to carry exactly what the
// module is allowed to retain, and no more.
const maxInventoryEntities = 4096

// entityRecord is one retained entity and the event that last described it.
type entityRecord struct {
	ev platform.Event
	// seq preserves announcement order, so the shipped payload is stable
	// between cycles rather than reordering with every map iteration.
	seq int64
}

// foldInventory folds entity events into the exporter's retained set and
// returns the current inventory in a stable order.
//
// Removal is a real delete rather than a tombstone. A tombstone would have to
// be aged out on some schedule, and an entity the agent has stopped observing
// is exactly what should stop being reported.
func (e *Exporter) foldInventory(events []platform.Event) []platform.Event {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.inventory == nil {
		e.inventory = make(map[string]*entityRecord)
	}
	for _, ev := range events {
		if !strings.HasPrefix(ev.Name, "discovery.entity.") {
			continue
		}
		key := inventoryKey(ev)
		if key == "" {
			continue
		}
		if ev.Name == "discovery.entity.removed" {
			delete(e.inventory, key)
			continue
		}
		if ev.Name != "discovery.entity.discovered" && ev.Name != "discovery.entity.changed" {
			continue
		}
		if rec, ok := e.inventory[key]; ok {
			// An update keeps its original position, so a container that
			// changes status does not jump to the end of the list.
			rec.ev = ev
			continue
		}
		// Past the cap, drop rather than grow. The agent must not turn a host
		// churning through short-lived entities into unbounded memory.
		if len(e.inventory) >= maxInventoryEntities {
			e.droppedInventory++
			continue
		}
		e.invSeq++
		e.inventory[key] = &entityRecord{ev: ev, seq: e.invSeq}
	}

	out := make([]*entityRecord, 0, len(e.inventory))
	for _, rec := range e.inventory {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })

	evs := make([]platform.Event, len(out))
	for i, rec := range out {
		evs[i] = rec.ev
	}
	return evs
}

// inventoryKey identifies the entity an event describes.
//
// The platform's own entity ID is the key whenever the entity resolved to one,
// because that is the identifier everything else in the agent already agrees
// on. The fallback exists for entities the platform could not name, and is
// built from whatever actually identifies that kind -- a container by its ID, a
// filesystem by its mount point, an endpoint by its address and port.
//
// The display name is deliberately NOT part of any key. Enabling container
// enrichment renames every container from its ID to its real name, and a key
// containing the name would read that as a fleet of new containers rather than
// as the same ones, described better.
func inventoryKey(ev platform.Event) string {
	attrs := make(map[string]string, len(ev.Attrs))
	for _, a := range ev.Attrs {
		attrs[a.Key] = a.Value
	}
	if id := attrs["entity.target.id"]; id != "" {
		return id
	}

	kind := attrs["entity.kind"]
	switch kind {
	case "container":
		return kind + "|" + attrs["container_id"]
	case "filesystem":
		return kind + "|" + attrs["mountpoint"]
	case "network_interface":
		return kind + "|" + attrs["interface"]
	case "network_endpoint":
		return kind + "|" + attrs["protocol"] + "|" + attrs["address"] + "|" + attrs["port"]
	case "host", "runtime", "cloud_instance":
		// Singletons: a host has exactly one of each, so the kind is the key.
		return kind
	case "kubernetes_pod":
		if uid := attrs["pod_uid"]; uid != "" {
			return kind + "|" + uid
		}
		return kind + "|" + attrs["namespace"] + "/" + attrs["pod"]
	case "process":
		return kind + "|" + attrs["name"] + "|" + attrs["pid"]
	case "":
		return ""
	default:
		name := attrs["name"]
		if name == "" {
			name = attrs["display_name"]
		}
		if name == "" {
			return ""
		}
		return kind + "|" + name
	}
}
