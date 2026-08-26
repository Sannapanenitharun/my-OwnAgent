package fleet

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func metricsBody(host string, names []string, value float64) []byte {
	body := `{"schema":"obsagent.v1","signal":"metrics","host":"` + host +
		`","resource":{"host.id":"` + host + `","cloud.provider":"aws","service.version":"9.9.9"},"metrics":{"gauges":[`
	for i, n := range names {
		if i > 0 {
			body += ","
		}
		body += fmt.Sprintf(`{"name":%q,"value":%v,"attributes":{"entity.id":%q}}`, n, value, host)
	}
	return []byte(body + `]}}`)
}

func TestIngestBuildsSummaryFromRealMetricNames(t *testing.T) {
	s := New(Limits{})
	body := []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"web-1",
		"resource":{"host.id":"i-abc","cloud.provider":"aws","service.version":"0.4.2"},
		"metrics":{"gauges":[
			{"name":"host.info","value":1,"attributes":{"os":"linux","platform":"Ubuntu","platform_version":"24.04","architecture":"amd64","entity.id":"i-abc"}},
			{"name":"host.cpu.utilization","value":0.42,"attributes":{"state":"busy"}},
			{"name":"host.cpu.utilization","value":0.10,"attributes":{"state":"user"}},
			{"name":"host.memory.used_bytes","value":800},
			{"name":"host.memory.total_bytes","value":1000},
			{"name":"host.uptime_seconds","value":3600},
			{"name":"process.instances","value":141},
			{"name":"host.filesystem.utilization","value":0.30,"attributes":{"mountpoint":"/"}},
			{"name":"host.filesystem.utilization","value":0.91,"attributes":{"mountpoint":"/data"}}
		]}}`)
	if err := s.Ingest("metrics", body); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	f := s.Fleet()
	if f.Total != 1 || f.Live != 1 {
		t.Fatalf("total=%d live=%d, want 1/1", f.Total, f.Live)
	}
	got := f.Hosts[0]
	if got.Host != "web-1" || got.HostID != "i-abc" {
		t.Errorf("host=%q id=%q", got.Host, got.HostID)
	}
	if got.OS != "linux" || got.Platform != "Ubuntu" || got.Arch != "amd64" {
		t.Errorf("os identity not read from host.info: %+v", got)
	}
	if got.Provider != "aws" || got.Agent != "0.4.2" {
		t.Errorf("resource not carried: provider=%q agent=%q", got.Provider, got.Agent)
	}
	// CPU must come from state=busy, not from whichever state was seen last.
	if got.CPUPercent < 41.9 || got.CPUPercent > 42.1 {
		t.Errorf("cpu=%v, want ~42 (state=busy)", got.CPUPercent)
	}
	if got.MemPercent < 79.9 || got.MemPercent > 80.1 {
		t.Errorf("mem=%v, want ~80 derived from used/total", got.MemPercent)
	}
	// The fullest filesystem is the one worth surfacing, not the first or mean.
	if got.DiskPct < 90.9 || got.DiskPct > 91.1 {
		t.Errorf("disk=%v, want ~91 (fullest mount)", got.DiskPct)
	}
	if got.Uptime != 3600 || got.Processes != 141 {
		t.Errorf("uptime=%v processes=%v", got.Uptime, got.Processes)
	}
}

func TestSeriesCapDropsNewSeriesAndKeepsExisting(t *testing.T) {
	s := New(Limits{SeriesPerHost: 3})
	if err := s.Ingest("metrics", metricsBody("h", []string{"host.cpu.utilization", "a", "b"}, 1)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	// A burst of new series past the cap must not evict host.cpu.utilization:
	// process churn would otherwise push out the series the UI depends on.
	for i := 0; i < 50; i++ {
		if err := s.Ingest("metrics", metricsBody("h", []string{fmt.Sprintf("process.churn.%d", i)}, 7)); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	d, ok := s.Host("h")
	if !ok {
		t.Fatal("host missing")
	}
	if d.Series != 3 {
		t.Errorf("series=%d, want 3 (capped)", d.Series)
	}
	if d.Dropped != 50 {
		t.Errorf("dropped=%d, want 50", d.Dropped)
	}
	var found bool
	for _, m := range d.Metrics {
		if m.Name == "host.cpu.utilization" {
			found = true
		}
	}
	if !found {
		t.Error("host.cpu.utilization was evicted by churn; it must survive")
	}
}

func TestHistoryIsBoundedAndOnlyForHostSeries(t *testing.T) {
	s := New(Limits{HistoryPoints: 5})
	for i := 0; i < 20; i++ {
		if err := s.Ingest("metrics", metricsBody("h", []string{"host.cpu.utilization", "process.memory.rss"}, float64(i))); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}
	d, _ := s.Host("h")
	for _, m := range d.Metrics {
		switch m.Name {
		case "host.cpu.utilization":
			if len(m.History) != 5 {
				t.Errorf("history=%d, want 5 (ring cap)", len(m.History))
			}
			// The ring must keep the newest samples, not the oldest.
			if m.History[len(m.History)-1].Value != 19 {
				t.Errorf("newest sample=%v, want 19", m.History[len(m.History)-1].Value)
			}
		case "process.memory.rss":
			if len(m.History) != 0 {
				t.Errorf("process.* kept %d history points; only host.* should", len(m.History))
			}
		}
	}
}

func TestHistorySeriesCapLeavesLatestValuesIntact(t *testing.T) {
	s := New(Limits{HistorySeries: 2})
	names := []string{"host.a", "host.b", "host.c", "host.d"}
	if err := s.Ingest("metrics", metricsBody("h", names, 3)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	d, _ := s.Host("h")
	if len(d.Metrics) != len(names) {
		t.Fatalf("metrics=%d, want %d: the cap limits history, not latest values", len(d.Metrics), len(names))
	}
	withHistory := 0
	for _, m := range d.Metrics {
		if len(m.History) > 0 {
			withHistory++
		}
	}
	if withHistory > 2 {
		t.Errorf("%d series kept history, cap is 2", withHistory)
	}
}

func TestHostCapEvictsStalestHost(t *testing.T) {
	s := New(Limits{Hosts: 2})
	base := time.Now()
	s.now = func() time.Time { return base }
	if err := s.Ingest("metrics", metricsBody("old", []string{"host.a"}, 1)); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(time.Minute) }
	if err := s.Ingest("metrics", metricsBody("mid", []string{"host.a"}, 1)); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if err := s.Ingest("metrics", metricsBody("new", []string{"host.a"}, 1)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Host("old"); ok {
		t.Error("stalest host was not evicted at the cap")
	}
	if _, ok := s.Host("new"); !ok {
		t.Error("newest host missing")
	}
	if got := s.Fleet().Total; got != 2 {
		t.Errorf("total=%d, want 2", got)
	}
}

func TestStaleFlagFollowsSilence(t *testing.T) {
	s := New(Limits{StaleAfter: 30 * time.Second})
	base := time.Now()
	s.now = func() time.Time { return base }
	if err := s.Ingest("metrics", metricsBody("h", []string{"host.a"}, 1)); err != nil {
		t.Fatal(err)
	}
	if s.Fleet().Hosts[0].Stale {
		t.Error("host stale immediately after reporting")
	}
	s.now = func() time.Time { return base.Add(31 * time.Second) }
	f := s.Fleet()
	if !f.Hosts[0].Stale {
		t.Error("host not marked stale after the window")
	}
	if f.Live != 0 {
		t.Errorf("live=%d, want 0", f.Live)
	}
}

func TestLogsAndSpansRingNewestFirst(t *testing.T) {
	s := New(Limits{LogsPerHost: 3, SpansPerHost: 2})
	for i := 0; i < 6; i++ {
		body := fmt.Sprintf(`{"schema":"obsagent.v1","signal":"logs","host":"h","logs":[{"message":"m%d","status":"info"}]}`, i)
		if err := s.Ingest("logs", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"schema":"obsagent.v1","signal":"traces","host":"h","spans":[{"trace_id":"t%d","span_id":"s%d","name":"op%d"}]}`, i, i, i)
		if err := s.Ingest("traces", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	d, _ := s.Host("h")
	if len(d.Logs) != 3 {
		t.Fatalf("logs=%d, want 3", len(d.Logs))
	}
	if d.Logs[0].Message != "m5" {
		t.Errorf("newest log = %q, want m5", d.Logs[0].Message)
	}
	if len(d.Spans) != 2 {
		t.Fatalf("spans=%d, want 2", len(d.Spans))
	}
	if d.Spans[0].Name != "op4" {
		t.Errorf("newest span = %q, want op4", d.Spans[0].Name)
	}
	if d.BatchLogs != 6 || d.BatchTraces != 5 {
		t.Errorf("batch counters lost: logs=%d traces=%d", d.BatchLogs, d.BatchTraces)
	}
}

func TestHostFallsBackToResourceIDWhenHostFieldMissing(t *testing.T) {
	s := New(Limits{})
	body := []byte(`{"schema":"obsagent.v1","signal":"metrics","resource":{"host.id":"i-xyz"},"metrics":{"gauges":[{"name":"host.a","value":1}]}}`)
	if err := s.Ingest("metrics", body); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Host("i-xyz"); !ok {
		t.Error("host not keyed by resource host.id when the host field is absent")
	}
}

func TestIngestRejectsInvalidJSONWithoutPanicking(t *testing.T) {
	s := New(Limits{})
	if err := s.Ingest("metrics", []byte("{not json")); err == nil {
		t.Error("want an error for malformed JSON")
	}
	if s.Fleet().Total != 0 {
		t.Error("a malformed batch created a host")
	}
}

func TestConcurrentIngestAndRead(t *testing.T) {
	s := New(Limits{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			host := fmt.Sprintf("h%d", n%3)
			for j := 0; j < 50; j++ {
				_ = s.Ingest("metrics", metricsBody(host, []string{"host.cpu.utilization"}, float64(j)))
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				f := s.Fleet()
				for _, h := range f.Hosts {
					_, _ = s.Host(h.Host)
				}
			}
		}()
	}
	wg.Wait()
	if got := s.Fleet().Total; got != 3 {
		t.Errorf("total=%d, want 3", got)
	}
}

func TestProcessCountSumsPerExecutableSeries(t *testing.T) {
	// process.instances arrives once per executable. Reading any single series
	// reported "1 process" on a real host running hundreds.
	s := New(Limits{})
	body := []byte(`{"schema":"obsagent.v1","signal":"metrics","host":"h","metrics":{"gauges":[
		{"name":"process.instances","value":1,"attributes":{"executable":"sshd"}},
		{"name":"process.instances","value":4,"attributes":{"executable":"nginx"}},
		{"name":"process.instances","value":12,"attributes":{"executable":"chrome"}}
	]}}`)
	if err := s.Ingest("metrics", body); err != nil {
		t.Fatal(err)
	}
	if got := s.Fleet().Hosts[0].Processes; got != 17 {
		t.Errorf("processes=%v, want 17 (sum across executables)", got)
	}
}
