package fleet

import (
	"sort"
	"strconv"
	"strings"
)

// InventoryItem is one discovered workload on a host.
type InventoryItem struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	// ID is the container ID, kept as a field rather than embedded in Detail.
	// Log lines carry a container ID and no name, so the view needs a reliable
	// join key; recovering one by parsing display text breaks the moment the
	// text changes.
	ID string `json:"id,omitempty"`
	// Detail is the one-line summary. It stays for the kinds that have no
	// columns of their own, and for a client too old to know the fields below.
	Detail string `json:"detail,omitempty"`

	// Container detail, shipped as separate fields rather than folded into
	// Detail so the view can lay containers out the way `docker ps` does. Each
	// is empty on a host without container enrichment, where a cgroup path
	// yields an ID and nothing else.
	Image   string `json:"image,omitempty"`
	Command string `json:"command,omitempty"`
	State   string `json:"state,omitempty"`
	Status  string `json:"status,omitempty"`
	Ports   string `json:"ports,omitempty"`
	// Created is Unix seconds, so the view can age it against the viewer's own
	// clock rather than trusting a pre-rendered "3 days ago" from the host.
	Created int64 `json:"created,omitempty"`

	CPU    float64 `json:"cpu,omitempty"`
	Memory float64 `json:"memory,omitempty"`
	Count  float64 `json:"count,omitempty"`
}

// Inventory is what runs on a host, grouped the way the drill-down shows it.
type Inventory struct {
	Containers []InventoryItem `json:"containers"`
	Services   []InventoryItem `json:"services"`
	Processes  []InventoryItem `json:"processes"`
	Endpoints  []InventoryItem `json:"endpoints"`
	Other      []InventoryItem `json:"other"`
}

// entity is a discovered thing, folded from the event stream. Entities are
// keyed so a repeated send is idempotent: the agent ships its full retained
// set each cycle rather than a delta, which makes the view self-healing after
// a restart or a dropped batch.
type entity struct {
	kind   string
	name   string
	detail string
	id     string
	gone   bool

	// Container detail, when the runtime API supplied it.
	image, command, state, status, ports string
	created                              int64
}

// ingestEvents folds discovery entity events into the host's entity table.
// The caller holds s.mu.
func (s *Store) ingestEventsLocked(h *host, events []eventJSON) {
	for _, ev := range events {
		ent, key := entityFromAttrs(ev.Attributes)
		if key == "" {
			continue
		}
		switch ev.Name {
		case "discovery.entity.discovered", "discovery.entity.changed":
			if ent.kind == "" || ent.name == "" {
				continue
			}
			// Past the cap, drop rather than grow: a host churning through
			// short-lived entities must not push the store into memory it
			// cannot bound.
			if _, seen := h.entities[key]; !seen && len(h.entities) >= s.limits.EntitiesPerHost {
				h.dropped++
				continue
			}
			e := ent
			h.entities[key] = &e
		case "discovery.entity.removed":
			if e, ok := h.entities[key]; ok {
				e.gone = true
			}
		}
	}
}

// inventory builds the grouped view for one host. Applications come from the
// process.* metric series rather than entity events, because the agent reports
// processes as aggregated per-executable metrics, not as discovered entities.
func (s *Store) inventoryLocked(h *host) Inventory {
	var inv Inventory
	for _, e := range h.entities {
		if e.gone || e.name == "" {
			continue
		}
		item := InventoryItem{
			Kind: e.kind, Name: e.name, Detail: e.detail, ID: e.id,
			Image: e.image, Command: e.command, State: e.state,
			Status: e.status, Ports: e.ports, Created: e.created,
		}
		switch e.kind {
		case "container":
			inv.Containers = append(inv.Containers, item)
		case "service":
			inv.Services = append(inv.Services, item)
		case "network_endpoint":
			inv.Endpoints = append(inv.Endpoints, item)
		case "process":
			inv.Processes = append(inv.Processes, item)
		default:
			inv.Other = append(inv.Other, item)
		}
	}

	// Fold per-executable process series into one row each.
	type proc struct {
		cpu, mem, count float64
	}
	byExe := map[string]*proc{}
	get := func(attrs map[string]string) *proc {
		name := attrs["executable"]
		if name == "" {
			name = attrs["name"]
		}
		if name == "" {
			return nil
		}
		p := byExe[name]
		if p == nil {
			p = &proc{}
			byExe[name] = p
		}
		return p
	}
	for _, ser := range h.series {
		if !strings.HasPrefix(ser.name, "process.") || ser.attrs == nil {
			continue
		}
		p := get(ser.attrs)
		if p == nil {
			continue
		}
		switch ser.name {
		case "process.cpu.utilization":
			p.cpu += ser.value
		case "process.memory.rss":
			p.mem += ser.value
		case "process.instances":
			p.count += ser.value
		}
	}
	for name, p := range byExe {
		if p.count == 0 && p.mem == 0 && p.cpu == 0 {
			continue
		}
		detail := ""
		if p.count > 0 {
			detail = "instances=" + trimFloat(p.count)
		}
		inv.Processes = append(inv.Processes, InventoryItem{
			Kind: "process", Name: name, Detail: detail,
			CPU: p.cpu, Memory: p.mem, Count: p.count,
		})
	}

	sortItems(inv.Containers)
	sortItems(inv.Services)
	sortItems(inv.Endpoints)
	sortItems(inv.Other)
	// Applications sort by memory: the biggest consumer is what an operator
	// opening this view is usually looking for.
	sort.Slice(inv.Processes, func(i, j int) bool {
		if inv.Processes[i].Memory != inv.Processes[j].Memory {
			return inv.Processes[i].Memory > inv.Processes[j].Memory
		}
		return inv.Processes[i].Name < inv.Processes[j].Name
	})
	return inv
}

func sortItems(items []InventoryItem) {
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
}

func trimFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// entityFromAttrs derives the kind, display name, detail line, and dedup key
// for one entity event. It mirrors the agent's own inventory view so the same
// events produce the same rows in both places.
func entityFromAttrs(attrs map[string]string) (e entity, key string) {
	kind := first(attrs, "entity.kind", "kind")
	name := first(attrs, "name", "display_name")
	detail := ""
	containerID := attrs["container_id"]
	runtime := attrs["runtime"]
	state := attrs["state"]
	address := attrs["address"]
	port := attrs["port"]
	protocol := attrs["protocol"]

	if name == "" {
		name = containerID
	}
	if name == "" && address != "" {
		name = address
		if port != "" {
			name += ":" + port
		}
	}

	switch kind {
	case "container":
		e.image = attrs["image"]
		e.command = attrs["command"]
		e.state = state
		e.status = attrs["status"]
		e.ports = attrs["ports"]
		if c := attrs["created"]; c != "" {
			// A created time the agent could not read is absent, not zero.
			if n, err := strconv.ParseInt(c, 10, 64); err == nil {
				e.created = n
			}
		}
		// Prefer what the runtime API supplied. Without enrichment the only
		// name available is the container ID, which is why an unenriched host
		// lists 64-character hex strings.
		parts := []string{}
		if img := attrs["image"]; img != "" {
			parts = append(parts, img)
		}
		if st := attrs["status"]; st != "" {
			parts = append(parts, st)
		} else if state != "" {
			parts = append(parts, state)
		}
		if p := attrs["ports"]; p != "" {
			parts = append(parts, p)
		}
		if len(parts) > 0 {
			detail = strings.Join(parts, " | ")
			break
		}
		// Unenriched: the runtime and a truncated id are all that is known.
		fallback := []string{}
		if runtime != "" {
			fallback = append(fallback, "runtime="+runtime)
		}
		if containerID != "" {
			id := containerID
			if len(id) > 12 {
				id = id[:12]
			}
			fallback = append(fallback, "id="+id)
		}
		detail = strings.Join(fallback, " ")
	case "service":
		if state != "" {
			detail = "state=" + state
		}
	case "network_endpoint":
		detail = strings.TrimSpace(protocol + " " + address)
		if port != "" {
			if detail != "" {
				detail += ":"
			}
			detail += port
		}
	}

	if kind == "" && name == "" {
		return entity{}, ""
	}
	// A container is identified by its ID. Its name is a description that can
	// change -- enabling enrichment renames every container from its ID to its
	// real name -- and a key containing the name would make that rename look
	// like 21 new containers rather than 21 updates.
	if kind == "container" && containerID != "" {
		key = kind + "|" + containerID
	} else {
		key = kind + "|" + name + "|" + containerID
	}
	e.kind, e.name, e.detail, e.id = kind, name, strings.TrimSpace(detail), containerID
	return e, key
}

func first(attrs map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := attrs[k]; v != "" {
			return v
		}
	}
	return ""
}

// inventoryCountsLocked counts entities by category without materialising the
// full item lists, so the fleet list can show what a host has without paying
// for the whole drill-down on every poll.
func (s *Store) inventoryCountsLocked(h *host) map[string]int {
	counts := map[string]int{}
	for _, e := range h.entities {
		if e.gone || e.name == "" {
			continue
		}
		switch e.kind {
		case "container":
			counts["containers"]++
		case "service":
			counts["services"]++
		case "network_endpoint":
			counts["endpoints"]++
		case "process":
			counts["processes"]++
		default:
			counts["other"]++
		}
	}
	seen := map[string]bool{}
	for _, ser := range h.series {
		if !strings.HasPrefix(ser.name, "process.") || ser.attrs == nil {
			continue
		}
		name := ser.attrs["executable"]
		if name == "" {
			name = ser.attrs["name"]
		}
		if name != "" && !seen[name] {
			seen[name] = true
			counts["processes"]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}
