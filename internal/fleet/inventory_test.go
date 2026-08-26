package fleet

import (
	"fmt"
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
