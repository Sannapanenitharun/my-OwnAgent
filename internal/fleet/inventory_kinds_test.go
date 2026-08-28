package fleet

import (
	"sort"
	"testing"
	"time"
)

// TestEveryEntityKindSurvivesIngest is the regression test for the defect this
// change exists to fix: the store named entities from an attribute literally
// called "name", and every kind that identifies itself some other way --
// filesystems by mountpoint, hosts by hostname, cloud instances by instance ID
// -- was silently discarded on arrival.
func TestEveryEntityKindSurvivesIngest(t *testing.T) {
	cases := []struct {
		kind  string
		attrs string
		want  string
		group func(Inventory) []InventoryItem
	}{
		{"filesystem", `"mountpoint":"/var","device":"/dev/nvme0n1p1","fstype":"ext4"`, "/var",
			func(i Inventory) []InventoryItem { return i.Filesystems }},
		{"host", `"hostname":"teleport","os":"linux","kernel":"6.8.0"`, "teleport",
			func(i Inventory) []InventoryItem { return i.Other }},
		{"cloud_instance", `"provider":"aws","instance_id":"i-00aab1097c1a58ac5"`, "i-00aab1097c1a58ac5",
			func(i Inventory) []InventoryItem { return i.Other }},
		{"runtime", `"in_container":"false"`, "bare metal or VM",
			func(i Inventory) []InventoryItem { return i.Other }},
		{"network_interface", `"interface":"eth0","up":"true","address":"172.31.36.199/20"`, "eth0",
			func(i Inventory) []InventoryItem { return i.Other }},
		{"kubernetes_pod", `"pod":"api-7d9","namespace":"prod","pod_uid":"abc"`, "prod/api-7d9",
			func(i Inventory) []InventoryItem { return i.Other }},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			s := New(Limits{})
			body := entityBody("h", "discovery.entity.discovered",
				`"entity.kind":"`+tc.kind+`",`+tc.attrs)
			if err := s.Ingest("inventory", body); err != nil {
				t.Fatal(err)
			}
			d, _ := s.Host("h")
			got := tc.group(d.Inventory)
			if len(got) != 1 {
				t.Fatalf("%s produced %d rows, want 1 -- the kind was dropped", tc.kind, len(got))
			}
			if got[0].Name != tc.want {
				t.Errorf("name = %q, want %q", got[0].Name, tc.want)
			}
		})
	}
}

func TestInterfacesAreNamedByInterfaceNotAddress(t *testing.T) {
	// Naming an interface from its addresses produced a row labelled
	// "172.31.36.199/20,fe80::.../64", and gave every address-less interface
	// the same empty key, collapsing them all onto one row.
	s := New(Limits{})
	for _, a := range []string{
		`"entity.kind":"network_interface","interface":"eth0","up":"true","address":"172.31.36.199/20"`,
		`"entity.kind":"network_interface","interface":"veth1","up":"true"`,
		`"entity.kind":"network_interface","interface":"veth2","up":"true"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	var names []string
	for _, it := range d.Inventory.Other {
		names = append(names, it.Name)
	}
	sort.Strings(names)
	if len(names) != 3 {
		t.Fatalf("interfaces = %v, want three distinct rows", names)
	}
	if names[0] != "eth0" || names[1] != "veth1" || names[2] != "veth2" {
		t.Errorf("names = %v, want the interface names", names)
	}
}

func TestServiceDetailIsNotThrownAway(t *testing.T) {
	// The agent reports the manager, the display name, whether the service
	// starts at boot, and its main PID. All four were discarded, so the table
	// could not distinguish "enabled but not running" from "not enabled" --
	// the question it exists to answer.
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"service","name":"ssh.service","display_name":"OpenBSD Secure Shell server",`+
			`"manager":"systemd","state":"running","enabled":"true","pid":"1234"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	svc := d.Inventory.Services[0]
	for _, tc := range []struct{ field, got, want string }{
		{"display_name", svc.DisplayName, "OpenBSD Secure Shell server"},
		{"manager", svc.Manager, "systemd"},
		{"state", svc.State, "running"},
		{"enabled", svc.Enabled, "true"},
		{"pid", svc.PID, "1234"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
}

func TestUnreportedEnabledIsDistinctFromDisabled(t *testing.T) {
	// A service manager that does not report enablement must not be rendered
	// as "does not start at boot"; they are different answers.
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"service","name":"sshd","state":"running"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if got := d.Inventory.Services[0].Enabled; got != "" {
		t.Errorf("enabled = %q, want empty when the manager did not say", got)
	}
}

func TestEndpointKeepsItsOwningPID(t *testing.T) {
	// "Port 11434 is open" is half an answer; the useful half is what is
	// listening on it.
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"network_endpoint","protocol":"tcp","address":"0.0.0.0","port":"11434","pid":"9182"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	ep := d.Inventory.Endpoints[0]
	if ep.Name != "0.0.0.0:11434" {
		t.Errorf("name = %q", ep.Name)
	}
	if ep.PID != "9182" || ep.Protocol != "tcp" || ep.Port != "11434" {
		t.Errorf("endpoint lost detail: %+v", ep)
	}
}

func TestEndpointsOnDifferentProtocolsAreDistinctRows(t *testing.T) {
	// A host can listen on tcp/53 and udp/53. Keying on the address alone
	// would show one.
	s := New(Limits{})
	for _, p := range []string{"tcp", "udp"} {
		body := entityBody("h", "discovery.entity.discovered",
			`"entity.kind":"network_endpoint","protocol":"`+p+`","address":"0.0.0.0","port":"53"`)
		if err := s.Ingest("inventory", body); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Endpoints) != 2 {
		t.Errorf("endpoints = %d, want tcp/53 and udp/53 as separate rows",
			len(d.Inventory.Endpoints))
	}
}

func TestFilesystemsCarryUsageFromTheMetricSeries(t *testing.T) {
	// A mount is an identity and its fullness is a measurement; they arrive on
	// different paths and the tab is only useful with both.
	s := New(Limits{})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"filesystem","mountpoint":"/","device":"/dev/root","fstype":"ext4"`)); err != nil {
		t.Fatal(err)
	}
	metrics := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"host.filesystem.total_bytes","value":100,"attributes":{"mountpoint":"/"}},
	  {"name":"host.filesystem.used_bytes","value":75,"attributes":{"mountpoint":"/"}},
	  {"name":"host.filesystem.utilization","value":0.75,"attributes":{"mountpoint":"/"}}]}}`
	if err := s.Ingest("metrics", []byte(metrics)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	fs := d.Inventory.Filesystems[0]
	if fs.TotalBytes != 100 || fs.UsedBytes != 75 {
		t.Errorf("size/used = %v/%v, want 100/75", fs.TotalBytes, fs.UsedBytes)
	}
	// The agent reports a fraction; the column is a percentage.
	if fs.UsedPercent != 75 {
		t.Errorf("used_percent = %v, want 75", fs.UsedPercent)
	}
}

func TestUnmeasuredFilesystemStillListed(t *testing.T) {
	// A mount with no series is still a mount. It must appear with no usage
	// rather than disappear.
	s := New(Limits{})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"filesystem","mountpoint":"/boot/efi","fstype":"vfat"`)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Filesystems) != 1 {
		t.Fatalf("filesystems = %d", len(d.Inventory.Filesystems))
	}
	if got := d.Inventory.Filesystems[0].UsedPercent; got != 0 {
		t.Errorf("used_percent = %v, want 0 for an unmeasured mount", got)
	}
}

func TestProcessEntityDoesNotDuplicateItsApplicationRow(t *testing.T) {
	// Linux truncates comm to 15 bytes, so a process entity arrives as
	// "clickhouse-serv" while the process module's metrics report
	// "clickhouse-server". Listing both gave every program two rows, one blank.
	s := New(Limits{})
	metrics := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":1024,"attributes":{"executable":"clickhouse-server"}},
	  {"name":"process.instances","value":2,"attributes":{"executable":"clickhouse-server"}}]}}`
	if err := s.Ingest("metrics", []byte(metrics)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"process","name":"clickhouse-serv","pid":"900"`)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if n := len(d.Inventory.Processes); n != 1 {
		var names []string
		for _, p := range d.Inventory.Processes {
			names = append(names, p.Name)
		}
		t.Fatalf("processes = %d %v, want one row for one program", n, names)
	}
	if got := d.Inventory.Processes[0].Name; got != "clickhouse-server" {
		t.Errorf("name = %q, want the untruncated executable name", got)
	}
}

func TestShortProcessNameIsNotTreatedAsATruncation(t *testing.T) {
	// Only a name at exactly the comm limit can be a truncation. "java" must
	// not be swallowed by an unrelated application called "javascript-thing".
	s := New(Limits{})
	metrics := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":1024,"attributes":{"executable":"javascript-thing"}}]}}`
	if err := s.Ingest("metrics", []byte(metrics)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"process","name":"java","pid":"7"`)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Processes) != 2 {
		t.Errorf("processes = %d, want java and javascript-thing as separate rows",
			len(d.Inventory.Processes))
	}
}

func TestUncoveredProcessEntityIsStillListed(t *testing.T) {
	// De-duplication must not become suppression: a process the metrics module
	// never rolled up is the one an operator most needs to see.
	s := New(Limits{})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"process","name":"sshd","pid":"7"`)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Processes) != 1 || d.Inventory.Processes[0].Name != "sshd" {
		t.Errorf("processes = %+v, want the uncovered entity", d.Inventory.Processes)
	}
}

func TestInventoryCountsMatchTheRowsRendered(t *testing.T) {
	// The chips are computed without materialising the lists, so they can drift
	// from the table. A chip reading "Applications 421" over 316 rows is worse
	// than no chip at all.
	s := New(Limits{})
	metrics := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":1024,"attributes":{"executable":"clickhouse-server"}}]}}`
	if err := s.Ingest("metrics", []byte(metrics)); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{
		`"entity.kind":"process","name":"clickhouse-serv","pid":"900"`,
		`"entity.kind":"process","name":"sshd","pid":"7"`,
		`"entity.kind":"filesystem","mountpoint":"/","fstype":"ext4"`,
		`"entity.kind":"container","name":"nginx","container_id":"abc123def456"`,
		`"entity.kind":"service","name":"ssh.service","state":"running"`,
		`"entity.kind":"network_endpoint","protocol":"tcp","address":"0.0.0.0","port":"22"`,
		`"entity.kind":"host","hostname":"teleport"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}

	d, _ := s.Host("h")
	counts := d.InvCounts
	for _, tc := range []struct {
		key  string
		rows []InventoryItem
	}{
		{"containers", d.Inventory.Containers},
		{"services", d.Inventory.Services},
		{"processes", d.Inventory.Processes},
		{"endpoints", d.Inventory.Endpoints},
		{"filesystems", d.Inventory.Filesystems},
		{"other", d.Inventory.Other},
	} {
		if counts[tc.key] != len(tc.rows) {
			t.Errorf("%s: chip says %d, table has %d", tc.key, counts[tc.key], len(tc.rows))
		}
	}
}

func TestWindowsVolumeUsageJoins(t *testing.T) {
	// Discovery reports the volume as "C:" and the filesystem metrics report
	// it as "C:\". An exact match found nothing, and every Windows drive
	// rendered as "not measured" with no error to show for it.
	s := New(Limits{})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"filesystem","mountpoint":"C:","fstype":"NTFS"`)); err != nil {
		t.Fatal(err)
	}
	metrics := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"host.filesystem.total_bytes","value":261189791744,"attributes":{"mountpoint":"C:\\"}},
	  {"name":"host.filesystem.utilization","value":0.9485,"attributes":{"mountpoint":"C:\\"}}]}}`
	if err := s.Ingest("metrics", []byte(metrics)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	fs := d.Inventory.Filesystems[0]
	if fs.TotalBytes != 261189791744 {
		t.Errorf("total = %v, want the volume size joined across the trailing separator", fs.TotalBytes)
	}
	if got := fs.UsedPercent; got < 94 || got > 95 {
		t.Errorf("used_percent = %v, want ~94.85", got)
	}
}

func TestRootMountIsNotTrimmedAway(t *testing.T) {
	// "/" is a mount point, not a trailing separator. Trimming it to the empty
	// string would drop the root filesystem out of the join entirely.
	if got := normalizeMount("/"); got != "/" {
		t.Errorf("normalizeMount(/) = %q, want /", got)
	}
	if got := normalizeMount("/var/"); got != "/var" {
		t.Errorf("normalizeMount(/var/) = %q, want /var", got)
	}
	if got := normalizeMount(`C:\`); got != "C:" {
		t.Errorf(`normalizeMount(C:\) = %q, want C:`, got)
	}
}

func TestExitedProgramsLeaveTheApplicationsList(t *testing.T) {
	// A program that exits stops being reported, but its last values sit in
	// the store forever. The tab listed 377 executables on a host running 232,
	// each dead one still showing the CPU and memory it had when it died.
	s := New(Limits{SeriesStaleAfter: time.Minute})
	old := `{"schema":"obsagent.v1","signal":"metrics","host":"h","timestamp":"2026-01-01T00:00:00Z","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":500,"attributes":{"executable":"gone"}}]}}`
	if err := s.Ingest("metrics", []byte(old)); err != nil {
		t.Fatal(err)
	}
	fresh := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":900,"attributes":{"executable":"alive"}}]}}`
	if err := s.Ingest("metrics", []byte(fresh)); err != nil {
		t.Fatal(err)
	}

	d, _ := s.Host("h")
	var names []string
	for _, p := range d.Inventory.Processes {
		names = append(names, p.Name)
	}
	if len(names) != 1 || names[0] != "alive" {
		t.Errorf("applications = %v, want only the program still running", names)
	}
	if d.InvCounts["processes"] != 1 {
		t.Errorf("chip says %d, want 1", d.InvCounts["processes"])
	}
}

func TestUnmountedFilesystemStopsReportingItsUsage(t *testing.T) {
	// A mount that went away must not keep claiming how full it was.
	s := New(Limits{SeriesStaleAfter: time.Minute})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"filesystem","mountpoint":"/mnt/gone","fstype":"ext4"`)); err != nil {
		t.Fatal(err)
	}
	stale := `{"schema":"obsagent.v1","signal":"metrics","host":"h","timestamp":"2026-01-01T00:00:00Z","metrics":{"gauges":[
	  {"name":"host.filesystem.total_bytes","value":100,"attributes":{"mountpoint":"/mnt/gone"}},
	  {"name":"host.filesystem.utilization","value":0.9,"attributes":{"mountpoint":"/mnt/gone"}}]}}`
	if err := s.Ingest("metrics", []byte(stale)); err != nil {
		t.Fatal(err)
	}
	// A later batch establishes that the host is still reporting.
	if err := s.Ingest("metrics", []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"host.cpu.utilization","value":0.1,"attributes":{}}]}}`)); err != nil {
		t.Fatal(err)
	}

	d, _ := s.Host("h")
	fs := d.Inventory.Filesystems[0]
	// The mount is still an entity, so it is still listed -- but with no usage.
	if fs.TotalBytes != 0 || fs.UsedPercent != 0 {
		t.Errorf("stale usage survived: total=%v pct=%v", fs.TotalBytes, fs.UsedPercent)
	}
}

func TestDeadSeriesAreReclaimedBeforeLiveOnesAreRefused(t *testing.T) {
	// Past the cap the store refuses NEW series, which is right -- churn must
	// not evict host.*. But dead series were counted against that cap, so a
	// host that churned through executables eventually rejected the ones that
	// still existed.
	s := New(Limits{SeriesPerHost: 3, SeriesStaleAfter: time.Minute})
	for _, exe := range []string{"a", "b", "c"} {
		body := `{"schema":"obsagent.v1","signal":"metrics","host":"h","timestamp":"2026-01-01T00:00:00Z",` +
			`"metrics":{"gauges":[{"name":"process.memory.rss","value":1,"attributes":{"executable":"` + exe + `"}}]}}`
		if err := s.Ingest("metrics", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	// The cap is full of series last seen in 2026-01-01. A live one arrives.
	live := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":42,"attributes":{"executable":"now"}}]}}`
	if err := s.Ingest("metrics", []byte(live)); err != nil {
		t.Fatal(err)
	}

	d, _ := s.Host("h")
	if len(d.Inventory.Processes) != 1 || d.Inventory.Processes[0].Name != "now" {
		t.Fatalf("applications = %+v, want the live program admitted", d.Inventory.Processes)
	}
}

func TestChartedSeriesAreNeverPruned(t *testing.T) {
	// host.* series carry the history the charts draw. Losing one to make room
	// for a process that has already exited would put a hole in a chart.
	s := New(Limits{SeriesPerHost: 2, SeriesStaleAfter: time.Minute})
	charted := `{"schema":"obsagent.v1","signal":"metrics","host":"h","timestamp":"2026-01-01T00:00:00Z","metrics":{"gauges":[
	  {"name":"host.cpu.utilization","value":0.5,"attributes":{"state":"busy"}},
	  {"name":"process.memory.rss","value":1,"attributes":{"executable":"dead"}}]}}`
	if err := s.Ingest("metrics", []byte(charted)); err != nil {
		t.Fatal(err)
	}
	newer := `{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
	  {"name":"process.memory.rss","value":2,"attributes":{"executable":"live"}}]}}`
	if err := s.Ingest("metrics", []byte(newer)); err != nil {
		t.Fatal(err)
	}

	d, _ := s.Host("h")
	var found bool
	for _, m := range d.Metrics {
		if m.Name == "host.cpu.utilization" {
			found = true
		}
	}
	if !found {
		t.Error("the charted host.* series was pruned to make room for a process")
	}
}

func TestUnidentifiedBatchIsRefusedNotMerged(t *testing.T) {
	// Filing unidentified batches under a shared name merges every agent that
	// failed identity resolution into one row, mixing the metrics of unrelated
	// machines -- and the more agents are broken, the more convincing that row
	// looks.
	s := New(Limits{})
	body := `{"schema":"obsagent.v1","signal":"metrics","metrics":{"gauges":[
	  {"name":"host.cpu.utilization","value":0.9,"attributes":{"state":"busy"}}]}}`
	if err := s.Ingest("metrics", []byte(body)); err == nil {
		t.Fatal("an unidentified batch was accepted")
	}
	if hosts := s.Fleet(); len(hosts.Hosts) != 0 {
		t.Errorf("hosts = %d, want none: there is no host to attribute this to", len(hosts.Hosts))
	}
}

func TestHostIDInResourceAttributesIsEnough(t *testing.T) {
	// The envelope's host field is the usual carrier, but an agent that puts
	// its identity only in the resource attributes is identified all the same.
	s := New(Limits{})
	body := `{"schema":"obsagent.v1","signal":"metrics","resource":{"host.id":"teleport"},"metrics":{"gauges":[
	  {"name":"host.cpu.utilization","value":0.9,"attributes":{"state":"busy"}}]}}`
	if err := s.Ingest("metrics", []byte(body)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if _, ok := s.Host("teleport"); !ok {
		t.Error("host not recorded from its resource attributes")
	}
}

func relBody(host, name, attrs string) []byte {
	return []byte(`{"schema":"obsagent.v1","signal":"inventory","host":"` + host +
		`","events":[{"name":"` + name + `","timestamp":"","attributes":{` + attrs + `}}]}`)
}

func TestTopologyNamesBothEndpoints(t *testing.T) {
	// The agent ships edges as platform entity IDs, which are correct and
	// unreadable. The view has to resolve them or the tab says nothing.
	s := New(Limits{})
	for _, a := range []string{
		`"entity.kind":"process","name":"sshd","pid":"1122415","entity.target.id":"p-1"`,
		`"entity.kind":"service","name":"ssh.service","state":"running","entity.target.id":"s-1"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Ingest("inventory", relBody("h", "discovery.relationship.discovered",
		`"relation":"runs_service","from.entity.id":"p-1","to.entity.id":"s-1","evidence":"cgroup_unit"`)); err != nil {
		t.Fatal(err)
	}

	d, _ := s.Host("h")
	if len(d.Inventory.Topology) != 1 {
		t.Fatalf("topology = %d edges, want 1", len(d.Inventory.Topology))
	}
	r := d.Inventory.Topology[0]
	if r.From != "sshd" || r.To != "ssh.service" {
		t.Errorf("edge = %q -> %q, want sshd -> ssh.service", r.From, r.To)
	}
	if r.FromKind != "process" || r.ToKind != "service" {
		t.Errorf("kinds = %q/%q", r.FromKind, r.ToKind)
	}
	if r.Evidence != "cgroup_unit" {
		t.Errorf("evidence = %q; an edge without it is an assertion", r.Evidence)
	}
	if d.InvCounts["topology"] != 1 {
		t.Errorf("chip says %d, want 1", d.InvCounts["topology"])
	}
}

func TestDanglingEdgeIsNotShown(t *testing.T) {
	// An edge whose endpoints are unknown would render as
	// "runs_service: 7f3a9c... -> 2b1e04...", which tells an operator less
	// than nothing. The chip must agree with the table.
	s := New(Limits{})
	if err := s.Ingest("inventory", relBody("h", "discovery.relationship.discovered",
		`"relation":"runs_service","from.entity.id":"ghost-1","to.entity.id":"ghost-2"`)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Topology) != 0 {
		t.Errorf("topology = %+v, want nothing renderable", d.Inventory.Topology)
	}
	if n := d.InvCounts["topology"]; n != 0 {
		t.Errorf("chip says %d over an empty table", n)
	}
}

func TestEdgeAppearsOnceItsEndpointsArrive(t *testing.T) {
	// Edges and entities arrive in the same batch but not in a guaranteed
	// order, and an edge can precede its endpoints across batches. It must not
	// be discarded for being early.
	s := New(Limits{})
	if err := s.Ingest("inventory", relBody("h", "discovery.relationship.discovered",
		`"relation":"endpoint_owned_by","from.entity.id":"e-1","to.entity.id":"p-1"`)); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Host("h"); len(d.Inventory.Topology) != 0 {
		t.Fatal("an edge rendered before its endpoints were known")
	}
	for _, a := range []string{
		`"entity.kind":"network_endpoint","protocol":"tcp","address":"0.0.0.0","port":"22","entity.target.id":"e-1"`,
		`"entity.kind":"process","name":"sshd","pid":"7","entity.target.id":"p-1"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Topology) != 1 {
		t.Fatalf("topology = %d, want the edge to appear once resolvable", len(d.Inventory.Topology))
	}
	if got := d.Inventory.Topology[0].From; got != "0.0.0.0:22" {
		t.Errorf("from = %q, want the endpoint", got)
	}
}

func TestRemovedRelationshipDisappears(t *testing.T) {
	s := New(Limits{})
	for _, a := range []string{
		`"entity.kind":"process","name":"sshd","pid":"7","entity.target.id":"p-1"`,
		`"entity.kind":"service","name":"ssh.service","entity.target.id":"s-1"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}
	attrs := `"relation":"runs_service","from.entity.id":"p-1","to.entity.id":"s-1"`
	if err := s.Ingest("inventory", relBody("h", "discovery.relationship.discovered", attrs)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest("inventory", relBody("h", "discovery.relationship.removed", attrs)); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Host("h"); len(d.Inventory.Topology) != 0 {
		t.Error("a removed relationship is still reported")
	}
}

func TestRepeatedEdgeIsNotDuplicated(t *testing.T) {
	// The agent re-sends its retained set every cycle.
	s := New(Limits{})
	for _, a := range []string{
		`"entity.kind":"process","name":"sshd","pid":"7","entity.target.id":"p-1"`,
		`"entity.kind":"service","name":"ssh.service","entity.target.id":"s-1"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 6; i++ {
		if err := s.Ingest("inventory", relBody("h", "discovery.relationship.discovered",
			`"relation":"runs_service","from.entity.id":"p-1","to.entity.id":"s-1"`)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Topology) != 1 {
		t.Errorf("topology = %d, want 1: a repeat is the same edge", len(d.Inventory.Topology))
	}
}

func TestEdgesAreBoundedSeparatelyFromEntities(t *testing.T) {
	// Edges outnumber nodes -- 477 against 395 on the measured host. A shared
	// budget would let a dense process tree crowd out the entities its edges
	// refer to, leaving edges that can never be named.
	s := New(Limits{EntitiesPerHost: 4, RelationsPerHost: 2})
	for _, a := range []string{
		`"entity.kind":"process","name":"a","pid":"1","entity.target.id":"p-1"`,
		`"entity.kind":"process","name":"b","pid":"2","entity.target.id":"p-2"`,
	} {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered", a)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		if err := s.Ingest("inventory", relBody("h", "discovery.relationship.discovered",
			`"relation":"parent_process","from.entity.id":"p-1","to.entity.id":"p-`+itoa(i)+`"`)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	// Both entities survive: the edge flood did not evict them.
	if n := len(d.Inventory.Processes); n != 2 {
		t.Errorf("processes = %d, want 2: edges must not evict nodes", n)
	}
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
