package fleet

import (
	"fmt"
	"strings"
	"testing"
)

func entityBody(host, name string, attrs string) []byte {
	return []byte(fmt.Sprintf(
		`{"schema":"obsagent.v1","signal":"inventory","host":%q,"events":[{"name":%q,"timestamp":"","attributes":{%s}}]}`,
		host, name, attrs))
}

func TestInventoryGroupsEntitiesByKind(t *testing.T) {
	s := New(Limits{})
	bodies := [][]byte{
		entityBody("h", "discovery.entity.discovered", `"entity.kind":"service","name":"nginx","state":"running"`),
		entityBody("h", "discovery.entity.discovered", `"entity.kind":"container","name":"api","runtime":"docker","container_id":"abcdef0123456789"`),
		entityBody("h", "discovery.entity.discovered", `"entity.kind":"network_endpoint","address":"0.0.0.0","port":"443","protocol":"tcp"`),
		entityBody("h", "discovery.entity.discovered", `"entity.kind":"mystery","name":"thing"`),
	}
	for _, b := range bodies {
		if err := s.Ingest("inventory", b); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	d, _ := s.Host("h")
	inv := d.Inventory
	if len(inv.Services) != 1 || inv.Services[0].Name != "nginx" {
		t.Errorf("services = %+v", inv.Services)
	}
	if inv.Services[0].Detail != "state=running" {
		t.Errorf("service detail = %q, want state=running", inv.Services[0].Detail)
	}
	if len(inv.Containers) != 1 || inv.Containers[0].Name != "api" {
		t.Fatalf("containers = %+v", inv.Containers)
	}
	// The container id is truncated for display; the full 64-char id is noise.
	if inv.Containers[0].Detail != "runtime=docker id=abcdef012345" {
		t.Errorf("container detail = %q", inv.Containers[0].Detail)
	}
	// An endpoint has no name of its own; address:port becomes the identity.
	if len(inv.Endpoints) != 1 || inv.Endpoints[0].Name != "0.0.0.0:443" {
		t.Errorf("endpoints = %+v", inv.Endpoints)
	}
	if len(inv.Other) != 1 || inv.Other[0].Name != "thing" {
		t.Errorf("unknown kinds must fall into Other, got %+v", inv.Other)
	}
}

func TestRemovedEntityLeavesTheInventory(t *testing.T) {
	s := New(Limits{})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"service","name":"nginx"`)); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Host("h"); len(d.Inventory.Services) != 1 {
		t.Fatal("service not recorded")
	}
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.removed",
		`"entity.kind":"service","name":"nginx"`)); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.Host("h"); len(d.Inventory.Services) != 0 {
		t.Error("removed service still listed")
	}
}

func TestRepeatedEntitySendIsIdempotent(t *testing.T) {
	// The agent ships its full retained entity set every cycle rather than a
	// delta, so the same entity arrives repeatedly. It must not accumulate.
	s := New(Limits{})
	for i := 0; i < 10; i++ {
		if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
			`"entity.kind":"service","name":"nginx","state":"running"`)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Services) != 1 {
		t.Errorf("services = %d after 10 identical sends, want 1", len(d.Inventory.Services))
	}
	if d.BatchInvent != 10 {
		t.Errorf("batches = %d, want 10", d.BatchInvent)
	}
}

func TestApplicationsComeFromProcessMetricsNotEntities(t *testing.T) {
	// Processes are reported as aggregated per-executable metrics, never as
	// discovery entities, so the Applications tab must be built from series.
	s := New(Limits{})
	body := []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
		{"name":"process.instances","value":29,"attributes":{"executable":"Code.exe"}},
		{"name":"process.memory.rss","value":2008473600,"attributes":{"executable":"Code.exe"}},
		{"name":"process.cpu.utilization","value":0.13,"attributes":{"executable":"Code.exe"}},
		{"name":"process.instances","value":6,"attributes":{"executable":"small.exe"}},
		{"name":"process.memory.rss","value":1024,"attributes":{"executable":"small.exe"}}
	]}}`)
	if err := s.Ingest("metrics", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	apps := d.Inventory.Processes
	if len(apps) != 2 {
		t.Fatalf("applications = %d, want 2", len(apps))
	}
	// Sorted by memory: the biggest consumer is what an operator opens this for.
	if apps[0].Name != "Code.exe" {
		t.Errorf("first application = %q, want the largest by memory", apps[0].Name)
	}
	if apps[0].Count != 29 || apps[0].Memory != 2008473600 {
		t.Errorf("application stats lost: %+v", apps[0])
	}
	if apps[0].Detail != "instances=29" {
		t.Errorf("detail = %q, want instances=29", apps[0].Detail)
	}
}

func TestEntityCapDropsRatherThanGrows(t *testing.T) {
	s := New(Limits{EntitiesPerHost: 3})
	for i := 0; i < 20; i++ {
		body := entityBody("h", "discovery.entity.discovered",
			fmt.Sprintf(`"entity.kind":"service","name":"svc-%d"`, i))
		if err := s.Ingest("inventory", body); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Services) != 3 {
		t.Errorf("services = %d, want 3 (capped)", len(d.Inventory.Services))
	}
	if d.Dropped == 0 {
		t.Error("dropped entities were not counted")
	}
}

func TestInventoryCountsMatchTheLists(t *testing.T) {
	s := New(Limits{})
	if err := s.Ingest("inventory", entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"service","name":"nginx"`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest("metrics", []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
		{"name":"process.instances","value":2,"attributes":{"executable":"a.exe"}}
	]}}`)); err != nil {
		t.Fatal(err)
	}
	f := s.Fleet()
	counts := f.Hosts[0].InvCounts
	if counts["services"] != 1 {
		t.Errorf("services count = %d, want 1", counts["services"])
	}
	// The summary count must agree with the list the drill-down renders, or the
	// chip says one thing and the table another.
	if counts["processes"] != 1 {
		t.Errorf("processes count = %d, want 1", counts["processes"])
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Processes) != counts["processes"] {
		t.Errorf("chip count %d disagrees with list length %d",
			counts["processes"], len(d.Inventory.Processes))
	}
}

func TestAgentWithoutInventoryExportStillReportsApplications(t *testing.T) {
	// An agent older than inventory export ships no entity events at all. Its
	// host must still show applications, derived from process metrics, and be
	// distinguishable by having received zero inventory batches.
	s := New(Limits{})
	if err := s.Ingest("metrics", []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"old","metrics":{"gauges":[
		{"name":"process.instances","value":3,"attributes":{"executable":"sshd"}}
	]}}`)); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("old")
	if d.BatchInvent != 0 {
		t.Errorf("batches_inventory = %d, want 0", d.BatchInvent)
	}
	if len(d.Inventory.Processes) != 1 {
		t.Errorf("applications = %d, want 1 from metrics alone", len(d.Inventory.Processes))
	}
	if len(d.Inventory.Services) != 0 {
		t.Error("services must be empty without entity events")
	}
}

func TestEnrichedContainerShowsNameImageAndPorts(t *testing.T) {
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","name":"grafana","image":"grafana/grafana:12.4.0",`+
			`"state":"running","status":"Up 3 days","ports":"3000->3000/tcp",`+
			`"runtime":"docker","container_id":"197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if len(d.Inventory.Containers) != 1 {
		t.Fatalf("containers = %d", len(d.Inventory.Containers))
	}
	c := d.Inventory.Containers[0]
	// The name must be the container's name, not its 64-character ID.
	if c.Name != "grafana" {
		t.Errorf("name = %q, want grafana", c.Name)
	}
	for _, want := range []string{"grafana/grafana:12.4.0", "Up 3 days", "3000->3000/tcp"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail %q is missing %q", c.Detail, want)
		}
	}
}

func TestUnenrichedContainerStillIdentifiesItself(t *testing.T) {
	// Without docker.socket configured there is no name or image, so the row
	// must fall back to runtime and a short ID rather than rendering blank.
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","runtime":"docker",`+
			`"container_id":"197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	c := d.Inventory.Containers[0]
	if c.Detail != "runtime=docker id=197a67528722" {
		t.Errorf("detail = %q, want the runtime and truncated id fallback", c.Detail)
	}
}

func TestEnrichingAContainerRenamesItRatherThanDuplicatingIt(t *testing.T) {
	// Turning on docker.socket changes a container's name from its 64-char ID
	// to its real name. That is the same container, so the inventory must show
	// one row, not two. Keying on the name produced 42 rows for 21 containers.
	s := New(Limits{})
	id := "197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"

	unenriched := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","name":"`+id+`","runtime":"docker","container_id":"`+id+`"`)
	if err := s.Ingest("inventory", unenriched); err != nil {
		t.Fatal(err)
	}
	enriched := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","name":"grafana","image":"grafana/grafana:12.4.0",`+
			`"status":"Up 3 days","runtime":"docker","container_id":"`+id+`"`)
	if err := s.Ingest("inventory", enriched); err != nil {
		t.Fatal(err)
	}

	d, _ := s.Host("h")
	if len(d.Inventory.Containers) != 1 {
		t.Fatalf("containers = %d, want 1: enrichment renames, it does not duplicate",
			len(d.Inventory.Containers))
	}
	if got := d.Inventory.Containers[0].Name; got != "grafana" {
		t.Errorf("name = %q, want the enriched name to win", got)
	}
}

func TestContainerInventoryCarriesItsIDAsAField(t *testing.T) {
	// Log lines carry a container ID and no name, so the view joins them to
	// the inventory on that ID. Recovering it by parsing the detail string
	// broke as soon as enrichment changed what that string contains.
	s := New(Limits{})
	id := "197a675287225cafa1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381"
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","name":"coroot","image":"ghcr.io/coroot/coroot:latest",`+
			`"status":"Up 25 hours","runtime":"docker","container_id":"`+id+`"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	c := d.Inventory.Containers[0]
	if c.ID != id {
		t.Errorf("ID = %q, want the full container id", c.ID)
	}
	// The detail is display text and must not be the join key.
	if strings.Contains(c.Detail, "id=") {
		t.Errorf("detail %q embeds the id; it belongs in the ID field", c.Detail)
	}
}

func TestContainerFieldsAreStructuredNotJustADetailLine(t *testing.T) {
	// The view lays containers out the way `docker ps` does, which means it
	// needs each fact in its own column. Splitting a joined detail string back
	// apart in the browser is how the ID field got lost the first time.
	s := New(Limits{})
	id := "cb6ed1f3ba58b0a1e9515ce3aa523f2fe04710a3aef8c72b4b7e6c80359381ab"
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","name":"juice-shop","image":"bkimminich/juice-shop",`+
			`"command":"/nodejs/bin/node /juice-shop/build/app.js","state":"running",`+
			`"status":"Up 28 hours","ports":"3030->3000/tcp","created":"1756000000",`+
			`"runtime":"docker","container_id":"`+id+`"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	c := d.Inventory.Containers[0]

	for _, tc := range []struct{ field, got, want string }{
		{"image", c.Image, "bkimminich/juice-shop"},
		{"command", c.Command, "/nodejs/bin/node /juice-shop/build/app.js"},
		{"state", c.State, "running"},
		{"status", c.Status, "Up 28 hours"},
		{"ports", c.Ports, "3030->3000/tcp"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if c.Created != 1756000000 {
		t.Errorf("created = %d, want the unix seconds the agent reported", c.Created)
	}
}

func TestUnreadableCreatedTimeIsAbsentNotEpochZero(t *testing.T) {
	// An unparsable timestamp must leave the field empty so the view renders a
	// dash. Falling through to 0 would age every such container from 1970.
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"container","name":"c","created":"not-a-number",`+
			`"runtime":"docker","container_id":"abc123def456"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	if got := d.Inventory.Containers[0].Created; got != 0 {
		t.Errorf("created = %d, want 0 (absent) for an unparsable value", got)
	}
}

func TestNonContainerKindsCarryNoContainerFields(t *testing.T) {
	// State is shared: a service has a run state just as a container does. The
	// container-only fields must stay empty, so the services table cannot grow
	// a column of dashes fed by something that never applies to it.
	s := New(Limits{})
	body := entityBody("h", "discovery.entity.discovered",
		`"entity.kind":"service","name":"sshd","state":"running"`)
	if err := s.Ingest("inventory", body); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Host("h")
	svc := d.Inventory.Services[0]
	if svc.State != "running" {
		t.Errorf("state = %q, want the service's own run state", svc.State)
	}
	if svc.Image != "" || svc.Status != "" || svc.Ports != "" || svc.Command != "" {
		t.Errorf("service carries container fields: image=%q status=%q ports=%q command=%q",
			svc.Image, svc.Status, svc.Ports, svc.Command)
	}
	if svc.Detail != "state=running" {
		t.Errorf("detail = %q, want the service's own summary", svc.Detail)
	}
}
