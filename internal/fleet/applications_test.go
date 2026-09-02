package fleet

import (
	"fmt"
	"testing"
)

func procMetrics(host, name, exe string, v float64) []byte {
	return []byte(fmt.Sprintf(
		`{"schema":"obsagent.v1","signal":"metrics","host":%q,"resource":{"host.id":%q},`+
			`"metrics":{"gauges":[{"name":%q,"value":%v,"attributes":{"executable":%q}}]}}`,
		host, host, name, v, exe))
}

// TestApplicationRowsCarryWhatTheAgentCollects. The process module ships eight
// things per executable and the tab was rendering three, discarding threads,
// file descriptors, virtual memory and disk I/O. Collecting a signal and
// dropping it at the last step costs exactly as much as collecting it and is
// worth exactly as much as not.
func TestApplicationRowsCarryWhatTheAgentCollects(t *testing.T) {
	s := New(Limits{})
	for _, m := range []struct {
		name string
		v    float64
	}{
		{"process.instances", 2},
		{"process.cpu.utilization", 0.5},
		{"process.memory.rss", 1024},
		{"process.thread.count", 40},
		{"process.open_files", 812},
		{"process.memory.virtual", 4096},
		{"process.io.read_bytes", 5000},
		{"process.io.write_bytes", 600},
	} {
		if err := s.Ingest("metrics", procMetrics("h1", m.name, "java", m.v)); err != nil {
			t.Fatalf("Ingest %s: %v", m.name, err)
		}
	}

	d, _ := s.Host("h1")
	var app InventoryItem
	for _, a := range d.Inventory.Processes {
		if a.Name == "java" {
			app = a
		}
	}
	if app.Name == "" {
		t.Fatal("the application row is missing")
	}
	for _, tc := range []struct {
		field string
		got   float64
		want  float64
	}{
		{"count", app.Count, 2},
		{"cpu", app.CPU, 0.5},
		{"memory", app.Memory, 1024},
		{"threads", app.Threads, 40},
		{"open files", app.OpenFiles, 812},
		{"virtual", app.VirtBytes, 4096},
		{"io read", app.IORead, 5000},
		{"io write", app.IOWrite, 600},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.field, tc.got, tc.want)
		}
	}
}

// TestPerExecutableValuesAreSummedNotAveraged. A row stands for every instance
// of the executable, so "java is holding 812 descriptors between its two
// processes" is the fact being reported.
func TestPerExecutableValuesAreSummedNotAveraged(t *testing.T) {
	s := New(Limits{})
	body := []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"h1","resource":{"host.id":"h1"},
		"metrics":{"gauges":[
			{"name":"process.open_files","value":400,"attributes":{"executable":"java","pid":"1"}},
			{"name":"process.open_files","value":412,"attributes":{"executable":"java","pid":"2"}},
			{"name":"process.instances","value":2,"attributes":{"executable":"java"}}]}}`)
	if err := s.Ingest("metrics", body); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	d, _ := s.Host("h1")
	for _, a := range d.Inventory.Processes {
		if a.Name == "java" && a.OpenFiles != 812 {
			t.Errorf("open files = %v, want 812", a.OpenFiles)
		}
	}
}
