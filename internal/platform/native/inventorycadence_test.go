package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/platform/inproc"
)

// eventBag is a real in-process Telemetry whose event snapshot the test
// controls. It embeds a working one rather than a nil interface because the
// exporter records its own counters through the same port, so a bare stub
// panics the moment a post is attempted.
type eventBag struct {
	*inproc.Telemetry
	events atomic.Value // []platform.Event
}

func (b *eventBag) set(evs []platform.Event) { b.events.Store(evs) }

func (b *eventBag) EventSnapshot() []platform.Event {
	v, _ := b.events.Load().([]platform.Event)
	return v
}

func invEntity(target, kind string, attrs ...platform.Attr) platform.Event {
	base := []platform.Attr{
		platform.A("entity.id", "i-123"),
		platform.A("entity.target.id", target),
		platform.A("entity.kind", kind),
		platform.A("change", "added"),
	}
	return platform.Event{
		Name:      "discovery.entity.discovered",
		Severity:  platform.SeverityInfo,
		Timestamp: time.Now(),
		Attrs:     append(base, attrs...),
	}
}

// inventoryProbe wires an exporter to a counting HTTP server.
func inventoryProbe(t *testing.T) (*Exporter, *eventBag, *int64, func()) {
	t.Helper()
	var posts int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/inventory" {
			atomic.AddInt64(&posts, 1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	bag := &eventBag{Telemetry: inproc.NewTelemetry()}
	bag.set(nil)
	e := New(bag, Config{
		Endpoint: srv.URL,
		Timeout:  2 * time.Second,
		Interval: time.Hour,
		MaxBatch: 64,
		Resource: []platform.Attr{platform.A("host.id", "i-123")},
	})
	e.client = srv.Client()
	return e, bag, &posts, srv.Close
}

// TestUnchangedInventoryIsNotResentEveryTick is the regression this guards.
//
// The inventory is full state and shares a tick with metrics, so it was shipped
// complete every five seconds. On a real host that was 711 entities re-sent 12
// times a minute -- 11.8 GB of archive in eight days, of which 98% announced
// nothing that was not already known.
func TestUnchangedInventoryIsNotResentEveryTick(t *testing.T) {
	e, bag, posts, stop := inventoryProbe(t)
	defer stop()

	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	bag.set([]platform.Event{
		invEntity("filesystem-aaa", "filesystem"),
		invEntity("process-bbb", "process"),
	})

	// First tick must send: nothing has gone out yet.
	e.exportInventory(context.Background(), base)
	if got := atomic.LoadInt64(posts); got != 1 {
		t.Fatalf("first tick posted %d times, want 1", got)
	}

	// Twenty more ticks across a minute and a half, with the same entities
	// re-announced each time, exactly as the discovery module does.
	for i := 1; i <= 20; i++ {
		bag.set([]platform.Event{
			invEntity("filesystem-aaa", "filesystem"),
			invEntity("process-bbb", "process"),
		})
		e.exportInventory(context.Background(), base.Add(time.Duration(i)*5*time.Second))
	}

	if got := atomic.LoadInt64(posts); got != 1 {
		t.Errorf("%d inventory posts after 21 ticks with no change, want 1", got)
	}
	if skipped := e.skippedInventory; skipped != 20 {
		t.Errorf("skipped counter = %d, want 20 -- suppressed posts must be countable", skipped)
	}
}

// TestAChangedInventoryGoesOutImmediately. Suppression must never delay real
// news: an entity appearing or disappearing is the thing the consumer is
// waiting for.
func TestAChangedInventoryGoesOutImmediately(t *testing.T) {
	e, bag, posts, stop := inventoryProbe(t)
	defer stop()
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	bag.set([]platform.Event{invEntity("filesystem-aaa", "filesystem")})
	e.exportInventory(context.Background(), base)

	bag.set([]platform.Event{invEntity("filesystem-aaa", "filesystem")})
	e.exportInventory(context.Background(), base.Add(5*time.Second))
	if got := atomic.LoadInt64(posts); got != 1 {
		t.Fatalf("posts = %d before any change, want 1", got)
	}

	// A new entity, one tick later.
	bag.set([]platform.Event{
		invEntity("filesystem-aaa", "filesystem"),
		invEntity("container-ccc", "container"),
	})
	e.exportInventory(context.Background(), base.Add(10*time.Second))
	if got := atomic.LoadInt64(posts); got != 2 {
		t.Errorf("posts = %d after a new entity appeared, want 2", got)
	}

	// A removal is equally news.
	bag.set([]platform.Event{{
		Name:      "discovery.entity.removed",
		Timestamp: base.Add(15 * time.Second),
		Attrs: []platform.Attr{
			platform.A("entity.id", "i-123"),
			platform.A("entity.target.id", "container-ccc"),
			platform.A("entity.kind", "container"),
		},
	}})
	e.exportInventory(context.Background(), base.Add(15*time.Second))
	if got := atomic.LoadInt64(posts); got != 3 {
		t.Errorf("posts = %d after a removal, want 3", got)
	}
}

// TestAnAlteredEntityCountsAsAChange. Re-announcing the same entity with a
// different payload -- a container changing status -- is news; re-announcing it
// identically is not.
func TestAnAlteredEntityCountsAsAChange(t *testing.T) {
	e, bag, posts, stop := inventoryProbe(t)
	defer stop()
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	bag.set([]platform.Event{invEntity("container-ccc", "container", platform.A("status", "running"))})
	e.exportInventory(context.Background(), base)

	// Identical: no post.
	bag.set([]platform.Event{invEntity("container-ccc", "container", platform.A("status", "running"))})
	e.exportInventory(context.Background(), base.Add(5*time.Second))
	if got := atomic.LoadInt64(posts); got != 1 {
		t.Fatalf("posts = %d on an identical re-announcement, want 1", got)
	}

	// Same entity, different status: a post.
	bag.set([]platform.Event{invEntity("container-ccc", "container", platform.A("status", "exited"))})
	e.exportInventory(context.Background(), base.Add(10*time.Second))
	if got := atomic.LoadInt64(posts); got != 2 {
		t.Errorf("posts = %d after the status changed, want 2", got)
	}
}

// TestTheUnchangedInventoryIsStillResentPeriodically. The payload is full
// state, and that is what lets a consumer which restarted or lost its store
// recover without the agent knowing anything went wrong. Suppression must not
// become silence.
func TestTheUnchangedInventoryIsStillResentPeriodically(t *testing.T) {
	e, bag, posts, stop := inventoryProbe(t)
	defer stop()
	base := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

	evs := []platform.Event{invEntity("filesystem-aaa", "filesystem")}
	bag.set(evs)
	e.exportInventory(context.Background(), base)

	// Just before the resend interval: still quiet.
	bag.set(evs)
	e.exportInventory(context.Background(), base.Add(inventoryResendInterval-time.Second))
	if got := atomic.LoadInt64(posts); got != 1 {
		t.Fatalf("posts = %d before the resend was due, want 1", got)
	}

	// At the interval: the full state goes out again, unchanged.
	bag.set(evs)
	e.exportInventory(context.Background(), base.Add(inventoryResendInterval))
	if got := atomic.LoadInt64(posts); got != 2 {
		t.Errorf("posts = %d at the resend interval, want 2 -- a consumer that lost its store must recover", got)
	}
}

// TestTheEventRingIsNotDrained. The obvious fix was to drain the events after
// export, and it would have been wrong twice: the local UI reads the same ring
// to show recent discovery activity, and full state is what makes the consumer
// self-healing.
func TestTheEventRingIsNotDrained(t *testing.T) {
	e, bag, _, stop := inventoryProbe(t)
	defer stop()

	evs := []platform.Event{
		invEntity("filesystem-aaa", "filesystem"),
		invEntity("process-bbb", "process"),
	}
	bag.set(evs)
	e.exportInventory(context.Background(), time.Now())

	if got := bag.EventSnapshot(); len(got) != len(evs) {
		t.Errorf("the snapshot holds %d events after export, want %d still retained "+
			"-- the local UI reads this ring", len(got), len(evs))
	}
}

// TestSameEvent pins the comparison the suppression depends on.
func TestSameEvent(t *testing.T) {
	a := invEntity("x", "filesystem", platform.A("mountpoint", "/"))
	b := invEntity("x", "filesystem", platform.A("mountpoint", "/"))
	b.Timestamp = a.Timestamp.Add(time.Hour)

	// The timestamp must be ignored: every re-announcement carries a fresh one,
	// so comparing it would make everything look new and suppress nothing.
	if !sameEvent(a, b) {
		t.Error("events differing only by timestamp were treated as different")
	}

	c := invEntity("x", "filesystem", platform.A("mountpoint", "/boot"))
	if sameEvent(a, c) {
		t.Error("a changed attribute value was treated as the same")
	}
	d := invEntity("x", "filesystem")
	if sameEvent(a, d) {
		t.Error("a missing attribute was treated as the same")
	}
	e2 := a
	e2.Name = "discovery.entity.changed"
	if sameEvent(a, e2) {
		t.Error("a different event name was treated as the same")
	}
}
