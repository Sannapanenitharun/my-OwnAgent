package fleet

import (
	"sort"
	"strconv"
	"strings"
)

// InventoryItem is one discovered thing on a host.
//
// The fields are deliberately explicit rather than a bag of attributes. The
// intake used to fold several facts into one display string and split it apart
// again in the browser, which lost the container ID and broke the log-to-name
// join; display text is not a data format. Every fact the view puts in its own
// column therefore gets its own field here.
type InventoryItem struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	// ID is the container ID. Log lines carry a container ID and no name, so
	// the view needs a reliable join key.
	ID string `json:"id,omitempty"`
	// Detail is the one-line summary, for kinds with no columns of their own.
	Detail string `json:"detail,omitempty"`

	// Container detail, empty on a host without container enrichment, where a
	// cgroup path yields an ID and nothing else.
	Image   string `json:"image,omitempty"`
	Command string `json:"command,omitempty"`
	Status  string `json:"status,omitempty"`
	Ports   string `json:"ports,omitempty"`
	// Created is Unix seconds, so the view ages it against the viewer's own
	// clock rather than trusting a pre-rendered "3 days ago" from the host.
	Created int64 `json:"created,omitempty"`

	// State is the run state, for both containers and services.
	State string `json:"state,omitempty"`

	// Service detail. Enabled is a string, not a bool, because "not reported"
	// and "does not start at boot" are different answers and an operator
	// chasing a service that failed to come up needs to tell them apart.
	DisplayName string `json:"display_name,omitempty"`
	Manager     string `json:"manager,omitempty"`
	Enabled     string `json:"enabled,omitempty"`

	// Endpoint detail. PID is also the service's main PID where one is known.
	Protocol string `json:"protocol,omitempty"`
	Address  string `json:"address,omitempty"`
	Port     string `json:"port,omitempty"`
	PID      string `json:"pid,omitempty"`

	// Filesystem detail. Size, Used and UsedPercent are joined in from the
	// host.filesystem.* series rather than carried on the entity: the mount is
	// an identity and its fullness is a measurement, and the agent reports
	// them on the two paths that suit them.
	Mountpoint  string  `json:"mountpoint,omitempty"`
	Device      string  `json:"device,omitempty"`
	FSType      string  `json:"fstype,omitempty"`
	ReadOnly    bool    `json:"read_only,omitempty"`
	Remote      bool    `json:"remote,omitempty"`
	TotalBytes  float64 `json:"total_bytes,omitempty"`
	UsedBytes   float64 `json:"used_bytes,omitempty"`
	UsedPercent float64 `json:"used_percent,omitempty"`

	CPU    float64 `json:"cpu,omitempty"`
	Memory float64 `json:"memory,omitempty"`
	Count  float64 `json:"count,omitempty"`
}

// Inventory is what runs on a host, grouped the way the drill-down shows it.
type Inventory struct {
	Containers  []InventoryItem `json:"containers"`
	Services    []InventoryItem `json:"services"`
	Processes   []InventoryItem `json:"processes"`
	Endpoints   []InventoryItem `json:"endpoints"`
	Filesystems []InventoryItem `json:"filesystems"`
	Other       []InventoryItem `json:"other"`
}

// entity is a discovered thing, folded from the event stream. Entities are
// keyed so a repeated send is idempotent: the agent ships its retained set
// each cycle rather than a delta, which makes the view self-healing after a
// restart or a dropped batch.
type entity struct {
	kind   string
	name   string
	detail string
	id     string
	gone   bool

	image, command, state, status, ports string
	created                              int64

	displayName, manager, enabled string
	protocol, address, port, pid  string

	mountpoint, device, fstype string
	readOnly, remote           bool
}

// ingestEventsLocked folds discovery entity events into the host's entity
// table. The caller holds s.mu.
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

// inventoryLocked builds the grouped view for one host.
func (s *Store) inventoryLocked(h *host) Inventory {
	var inv Inventory

	// Applications first, so a process entity can tell whether the executable
	// it belongs to is already accounted for.
	apps := s.applicationsLocked(h)
	covered := newAppIndex(apps)

	for _, e := range h.entities {
		if e.gone || e.name == "" {
			continue
		}
		item := InventoryItem{
			Kind: e.kind, Name: e.name, Detail: e.detail, ID: e.id,
			Image: e.image, Command: e.command, State: e.state,
			Status: e.status, Ports: e.ports, Created: e.created,
			DisplayName: e.displayName, Manager: e.manager, Enabled: e.enabled,
			Protocol: e.protocol, Address: e.address, Port: e.port, PID: e.pid,
			Mountpoint: e.mountpoint, Device: e.device, FSType: e.fstype,
			ReadOnly: e.readOnly, Remote: e.remote,
		}
		switch e.kind {
		case "container":
			inv.Containers = append(inv.Containers, item)
		case "service":
			inv.Services = append(inv.Services, item)
		case "network_endpoint":
			inv.Endpoints = append(inv.Endpoints, item)
		case "filesystem":
			inv.Filesystems = append(inv.Filesystems, item)
		case "process":
			// A process entity names itself from Linux's comm field, which is
			// truncated to 15 characters, while the process module's metrics
			// name the executable in full. Listing both produced two rows for
			// every program on the host -- "clickhouse-serv" with no numbers
			// beside "clickhouse-server" with all of them. The rollup is the
			// more useful row, so an entity is only shown when nothing already
			// covers it.
			if !covered.covers(e.name) {
				inv.Processes = append(inv.Processes, item)
			}
		default:
			inv.Other = append(inv.Other, item)
		}
	}
	inv.Processes = append(inv.Processes, apps...)

	s.joinFilesystemUsageLocked(h, inv.Filesystems)

	sortItems(inv.Containers)
	sortItems(inv.Services)
	sortItems(inv.Endpoints)
	sortItems(inv.Other)
	// Fullest filesystem first: an operator opening this tab is looking for
	// the one about to run out.
	sort.Slice(inv.Filesystems, func(i, j int) bool {
		if inv.Filesystems[i].UsedPercent != inv.Filesystems[j].UsedPercent {
			return inv.Filesystems[i].UsedPercent > inv.Filesystems[j].UsedPercent
		}
		return inv.Filesystems[i].Name < inv.Filesystems[j].Name
	})
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

// commLen is the length of Linux's comm field, minus its NUL. A process entity
// names itself from comm, so any longer executable name arrives truncated to
// exactly this many bytes.
const commLen = 15

// appIndex answers "is this process entity already covered by an application
// row" in constant time. Scanning the application list per entity would be
// hundreds of string comparisons per host per poll, and the fleet list polls
// every host.
type appIndex struct {
	names  map[string]bool
	truncs map[string]bool
}

func newAppIndex(apps []InventoryItem) appIndex {
	ix := appIndex{
		names:  make(map[string]bool, len(apps)),
		truncs: make(map[string]bool, len(apps)),
	}
	for _, a := range apps {
		ix.names[a.Name] = true
		if len(a.Name) > commLen {
			ix.truncs[a.Name[:commLen]] = true
		}
	}
	return ix
}

// covers reports whether a process entity is the same program as one of the
// rolled-up applications. An exact match is the common case; the truncation
// check catches comm, where "coroot-node-age" is the kernel's 15-byte
// rendering of "coroot-node-agent".
func (ix appIndex) covers(name string) bool {
	return ix.names[name] || (len(name) == commLen && ix.truncs[name])
}

// applicationsLocked folds the per-executable process series into one row each.
// Applications come from metrics rather than entity events because the agent
// reports processes as aggregated per-executable measurements -- which is what
// bounds their cardinality.
func (s *Store) applicationsLocked(h *host) []InventoryItem {
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

	out := make([]InventoryItem, 0, len(byExe))
	for name, p := range byExe {
		if p.count == 0 && p.mem == 0 && p.cpu == 0 {
			continue
		}
		detail := ""
		if p.count > 0 {
			detail = "instances=" + trimFloat(p.count)
		}
		out = append(out, InventoryItem{
			Kind: "process", Name: name, Detail: detail,
			CPU: p.cpu, Memory: p.mem, Count: p.count,
		})
	}
	return out
}

// joinFilesystemUsageLocked fills in how full each mount is from the
// host.filesystem.* series. The entity says a filesystem exists; the series
// says how much of it is left, and the tab is only useful with both.
func (s *Store) joinFilesystemUsageLocked(h *host, mounts []InventoryItem) {
	if len(mounts) == 0 {
		return
	}
	type usage struct{ total, used, pct float64 }
	byMount := map[string]*usage{}
	for _, ser := range h.series {
		if !strings.HasPrefix(ser.name, "host.filesystem.") || ser.attrs == nil {
			continue
		}
		mp := normalizeMount(ser.attrs["mountpoint"])
		if mp == "" {
			continue
		}
		u := byMount[mp]
		if u == nil {
			u = &usage{}
			byMount[mp] = u
		}
		switch ser.name {
		case "host.filesystem.total_bytes":
			u.total = ser.value
		case "host.filesystem.used_bytes":
			u.used = ser.value
		case "host.filesystem.utilization":
			u.pct = ser.value
		}
	}
	for i := range mounts {
		u := byMount[normalizeMount(mounts[i].Mountpoint)]
		if u == nil {
			continue
		}
		mounts[i].TotalBytes, mounts[i].UsedBytes = u.total, u.used
		// The agent reports utilization as a fraction; the view wants percent.
		mounts[i].UsedPercent = u.pct * 100
	}
}

// normalizeMount makes the two sides of the usage join agree about a trailing
// separator. On Windows the discovery entity reports the volume as "C:" while
// the filesystem metrics report "C:\", so an exact match found nothing and
// every Windows drive rendered as "not measured" -- with no error anywhere,
// because a failed join looks exactly like a mount the agent did not measure.
// The root of a Unix filesystem is left alone; "/" is a mount point, not a
// separator that can be trimmed away.
func normalizeMount(mp string) string {
	if len(mp) > 1 {
		mp = strings.TrimRight(mp, `/\`)
	}
	return mp
}

func sortItems(items []InventoryItem) {
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
}

func trimFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

// entityFromAttrs derives one entity and its dedup key from an event's
// attributes.
//
// Every kind names itself differently, and that is the whole of this function.
// A container carries "name", but a filesystem is identified by its mountpoint,
// an interface by its interface name, a host by its hostname, a cloud instance
// by its instance ID. Requiring an attribute literally called "name" silently
// discarded five of the twelve kinds the agent collects -- every filesystem,
// and the host, runtime and cloud-instance records -- because they name
// themselves with the field that actually identifies them.
func entityFromAttrs(attrs map[string]string) (e entity, key string) {
	kind := first(attrs, "entity.kind", "kind")
	containerID := attrs["container_id"]

	// ident is what makes this entity distinct from others of its kind. It is
	// kept separate from the display name because the two differ: enabling
	// container enrichment renames a container from its ID to its real name,
	// and a key built from the name would read that rename as 21 new
	// containers rather than 21 updates.
	name, ident, detail := "", "", ""

	switch kind {
	case "container":
		name = first(attrs, "name", "display_name")
		if name == "" {
			name = containerID
		}
		ident = containerID
		e.image = attrs["image"]
		e.command = attrs["command"]
		e.state = attrs["state"]
		e.status = attrs["status"]
		e.ports = attrs["ports"]
		if n, err := strconv.ParseInt(attrs["created"], 10, 64); err == nil {
			// A created time the agent could not read is absent, not zero.
			e.created = n
		}
		detail = containerDetail(attrs, containerID)

	case "service":
		name = first(attrs, "name", "display_name")
		ident = name
		e.state = attrs["state"]
		e.displayName = attrs["display_name"]
		e.manager = attrs["manager"]
		e.enabled = attrs["enabled"]
		e.pid = attrs["pid"]
		if e.state != "" {
			detail = "state=" + e.state
		}

	case "network_endpoint":
		e.protocol = attrs["protocol"]
		e.address = attrs["address"]
		e.port = attrs["port"]
		e.pid = attrs["pid"]
		name = e.address
		if e.port != "" {
			name += ":" + e.port
		}
		ident = e.protocol + "|" + e.address + "|" + e.port
		detail = strings.TrimSpace(e.protocol + " " + name)

	case "filesystem":
		e.mountpoint = attrs["mountpoint"]
		e.device = attrs["device"]
		e.fstype = attrs["fstype"]
		e.readOnly = attrs["read_only"] == "true"
		e.remote = attrs["remote"] == "true"
		name, ident = e.mountpoint, e.mountpoint
		detail = strings.TrimSpace(e.fstype + " " + e.device)

	case "network_interface":
		// Named by the interface, not by its addresses. Falling through to the
		// address made a row labelled "172.31.36.199/20,fe80::.../64", and gave
		// every address-less interface the same empty key -- so they collapsed
		// onto one row.
		name = attrs["interface"]
		ident = name
		e.address = attrs["address"]
		detail = interfaceDetail(attrs)

	case "host":
		name = first(attrs, "hostname", "name")
		ident = "host"
		detail = joinNonEmpty(" ", attrs["os"], attrs["distribution"],
			attrs["version"], attrs["kernel"], attrs["arch"])

	case "cloud_instance":
		name = first(attrs, "instance_id", "provider")
		ident = "cloud_instance"
		detail = joinNonEmpty(" ", attrs["provider"], attrs["vendor"], attrs["product"])

	case "runtime":
		if attrs["in_container"] == "true" {
			name = first(attrs, "runtime", "name")
			detail = "agent runs in a " + name + " container"
		} else {
			name = "bare metal or VM"
			detail = "agent runs directly on the host"
		}
		ident = "runtime"

	case "kubernetes_pod":
		name = joinNonEmpty("/", attrs["namespace"], attrs["pod"])
		ident = first(attrs, "pod_uid")
		if ident == "" {
			ident = name
		}
		detail = attrs["node"]

	case "process":
		name = first(attrs, "name", "display_name")
		e.pid = attrs["pid"]
		ident = name + "|" + e.pid

	default:
		// An unrecognised kind is still shown. A new entity kind on a newer
		// agent must degrade to a row with a name, not vanish.
		name = first(attrs, "name", "display_name", "hostname", "mountpoint", "interface")
		ident = name
	}

	if kind == "" || name == "" {
		return entity{}, ""
	}
	if ident == "" {
		ident = name
	}
	e.kind, e.name, e.detail, e.id = kind, name, strings.TrimSpace(detail), containerID
	return e, kind + "|" + ident
}

// containerDetail renders the one-line summary for a container. It is only a
// fallback now that each fact has its own column, but it stays honest for a
// host with no enrichment, where the runtime and a short ID are all that is
// known.
func containerDetail(attrs map[string]string, containerID string) string {
	parts := []string{}
	if img := attrs["image"]; img != "" {
		parts = append(parts, img)
	}
	if st := attrs["status"]; st != "" {
		parts = append(parts, st)
	} else if st := attrs["state"]; st != "" {
		parts = append(parts, st)
	}
	if p := attrs["ports"]; p != "" {
		parts = append(parts, p)
	}
	if len(parts) > 0 {
		return strings.Join(parts, " | ")
	}
	fallback := []string{}
	if runtime := attrs["runtime"]; runtime != "" {
		fallback = append(fallback, "runtime="+runtime)
	}
	if containerID != "" {
		id := containerID
		if len(id) > 12 {
			id = id[:12]
		}
		fallback = append(fallback, "id="+id)
	}
	return strings.Join(fallback, " ")
}

func interfaceDetail(attrs map[string]string) string {
	parts := []string{}
	if attrs["up"] == "true" {
		parts = append(parts, "up")
	} else if attrs["up"] == "false" {
		parts = append(parts, "down")
	}
	if a := attrs["address"]; a != "" {
		parts = append(parts, a)
	}
	if m := attrs["mac_address"]; m != "" {
		parts = append(parts, "mac="+m)
	}
	if m := attrs["mtu"]; m != "" {
		parts = append(parts, "mtu="+m)
	}
	return strings.Join(parts, " ")
}

func joinNonEmpty(sep string, vals ...string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return strings.Join(out, sep)
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
//
// It must group exactly as inventoryLocked does, including the application
// de-duplication: a chip reading "Applications 421" over a table of 316 rows
// is worse than no chip at all.
func (s *Store) inventoryCountsLocked(h *host) map[string]int {
	counts := map[string]int{}
	apps := s.applicationsLocked(h)
	covered := newAppIndex(apps)
	counts["processes"] = len(apps)

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
		case "filesystem":
			counts["filesystems"]++
		case "process":
			if !covered.covers(e.name) {
				counts["processes"]++
			}
		default:
			counts["other"]++
		}
	}
	for k, v := range counts {
		if v == 0 {
			delete(counts, k)
		}
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}
