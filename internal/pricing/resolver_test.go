package pricing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCatalog(region string, rates map[string]float64) *Catalog {
	c := &Catalog{
		Provider:  "aws",
		Region:    region,
		Published: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Fetched:   time.Now().UTC(),
		Rates:     map[string]Rate{},
	}
	for k, v := range rates {
		c.Rates[k] = Rate{Provider: "aws", Region: region, InstanceType: k, USDPerHour: v}
	}
	return c
}

// stubResolver returns a resolver whose fetch is controlled by the test, plus
// a channel that receives each region fetched.
func stubResolver(t *testing.T, dir string, cat *Catalog, err error) (*Resolver, chan string) {
	t.Helper()
	calls := make(chan string, 8)
	r := NewResolver(dir, &http.Client{})
	r.fetch = func(_ context.Context, _ *http.Client, region string) (*Catalog, error) {
		calls <- region
		return cat, err
	}
	return r, calls
}

// TestALookupNeverBlocksOnADownload is the resolver's central rule.
//
// Fetching a price list moves 300 MB and takes minutes. If a lookup waited for
// it, the first page render would hang for the length of a download. A miss
// must return immediately and arrange for a later answer.
func TestALookupNeverBlocksOnADownload(t *testing.T) {
	release := make(chan struct{})
	r := NewResolver("", &http.Client{})
	r.fetch = func(_ context.Context, _ *http.Client, region string) (*Catalog, error) {
		<-release // a download that has not finished
		return testCatalog(region, map[string]float64{"m5.large": 0.096}), nil
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, ok := r.Rate(context.Background(), "us-east-1", "m5.large"); ok {
			t.Error("a cold lookup returned a rate; it cannot have one yet")
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Rate() blocked waiting for a download")
	}
	close(release)
}

// TestTheFetchOutlivesTheRequestThatTriggeredIt. The caller's context belongs
// to an HTTP request that finishes in milliseconds; inheriting it would cancel
// every fetch the moment the page finished rendering.
func TestTheFetchOutlivesTheRequestThatTriggeredIt(t *testing.T) {
	// The fetch is held open until the test has cancelled the request context,
	// then asked whether its OWN context survived. Checking after the fetch
	// returns proves nothing: the deferred cancel has fired by then, which is
	// correct and looks identical to the bug.
	proceed := make(chan struct{})
	result := make(chan error, 1)

	r := NewResolver("", &http.Client{})
	r.fetch = func(ctx context.Context, _ *http.Client, region string) (*Catalog, error) {
		<-proceed
		result <- ctx.Err()
		return testCatalog(region, map[string]float64{"m5.large": 0.096}), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.Rate(ctx, "us-east-1", "m5.large")
	cancel() // the request ends immediately, as requests do
	close(proceed)

	select {
	case err := <-result:
		if err != nil {
			t.Errorf("the fetch context died with the request (%v); no download would ever finish", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no fetch was scheduled")
	}
}

func TestAScheduledFetchPopulatesTheCatalog(t *testing.T) {
	r, calls := stubResolver(t, "", testCatalog("us-east-1", map[string]float64{"m5.large": 0.096}), nil)

	if _, ok := r.Rate(context.Background(), "us-east-1", "m5.large"); ok {
		t.Fatal("cold lookup returned a rate")
	}
	select {
	case <-calls:
	case <-time.After(3 * time.Second):
		t.Fatal("no fetch scheduled")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rate, ok := r.Rate(context.Background(), "us-east-1", "m5.large"); ok {
			if rate.USDPerHour != 0.096 {
				t.Errorf("rate = %v", rate.USDPerHour)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the catalog never became available after a successful fetch")
}

// TestOnlyOneFetchPerRegionIsInFlight. Every render of a page with fifty hosts
// on it would otherwise start fifty downloads of the same file.
func TestOnlyOneFetchPerRegionIsInFlight(t *testing.T) {
	release := make(chan struct{})
	calls := make(chan string, 64)
	r := NewResolver("", &http.Client{})
	r.fetch = func(_ context.Context, _ *http.Client, region string) (*Catalog, error) {
		calls <- region
		<-release
		return testCatalog(region, map[string]float64{"m5.large": 0.096}), nil
	}

	for i := 0; i < 25; i++ {
		r.Rate(context.Background(), "us-east-1", "m5.large")
	}
	time.Sleep(150 * time.Millisecond)
	close(release)

	if n := len(calls); n != 1 {
		t.Errorf("%d fetches started for one region, want 1", n)
	}
}

// TestAFailedRegionIsNotRetriedImmediately. A typo in a region name must not
// schedule a 300 MB download on every page render.
func TestAFailedRegionIsNotRetriedImmediately(t *testing.T) {
	calls := make(chan string, 32)
	r := NewResolver("", &http.Client{})
	r.fetch = func(_ context.Context, _ *http.Client, region string) (*Catalog, error) {
		calls <- region
		return nil, errors.New("403 Forbidden")
	}

	r.Rate(context.Background(), "not-a-region", "m5.large")
	time.Sleep(150 * time.Millisecond)
	for i := 0; i < 10; i++ {
		r.Rate(context.Background(), "not-a-region", "m5.large")
	}
	time.Sleep(150 * time.Millisecond)

	if n := len(calls); n != 1 {
		t.Errorf("%d fetches for a failing region, want 1 until the retry window elapses", n)
	}
	st := r.Status()
	if len(st) != 1 || st[0].LastError == "" {
		t.Errorf("status did not surface the failure: %+v", st)
	}
}

// TestStaleBeatsNothing. Last month's list price is a better estimate than a
// blank column, and the refresh is already running.
func TestStaleBeatsNothing(t *testing.T) {
	old := testCatalog("us-east-1", map[string]float64{"m5.large": 0.09})
	old.Fetched = time.Now().Add(-90 * 24 * time.Hour)

	r, _ := stubResolver(t, "", testCatalog("us-east-1", map[string]float64{"m5.large": 0.096}), nil)
	if err := r.Put(old); err != nil {
		t.Fatal(err)
	}

	rate, ok := r.Rate(context.Background(), "us-east-1", "m5.large")
	if !ok {
		t.Fatal("a stale catalog returned nothing; the column would be blank for a whole download")
	}
	if rate.USDPerHour != 0.09 {
		t.Errorf("rate = %v, want the stale 0.09 until the refresh lands", rate.USDPerHour)
	}
	if st := r.Status(); len(st) != 1 || !st[0].Stale {
		t.Errorf("status did not mark the catalog stale: %+v", st)
	}
}

func TestDiskCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cat := testCatalog("eu-west-1", map[string]float64{"m5.large": 0.107, "t3.micro": 0.0114})

	w, _ := stubResolver(t, dir, cat, nil)
	w.saveToDisk(cat)

	path := filepath.Join(dir, "pricing-aws-eu-west-1.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}

	// A second resolver, with no memory, must read it back without fetching.
	calls := make(chan string, 4)
	r2 := NewResolver(dir, &http.Client{})
	r2.fetch = func(_ context.Context, _ *http.Client, region string) (*Catalog, error) {
		calls <- region
		return nil, errors.New("should not fetch")
	}
	rate, ok := r2.Rate(context.Background(), "eu-west-1", "m5.large")
	if !ok || rate.USDPerHour != 0.107 {
		t.Errorf("rate from disk = %+v ok=%v, want 0.107", rate, ok)
	}
	if len(calls) != 0 {
		t.Error("a fresh cache on disk still triggered a download")
	}
}

// TestACacheFileNamingOneRegionAndHoldingAnotherIsRejected. That file would
// price every host in the fleet wrongly, and consistently, which is the hardest
// kind of wrong to notice.
func TestACacheFileNamingOneRegionAndHoldingAnotherIsRejected(t *testing.T) {
	dir := t.TempDir()
	wrong := testCatalog("us-east-1", map[string]float64{"m5.large": 0.096})
	body, _ := json.Marshal(wrong)
	if err := os.WriteFile(filepath.Join(dir, "pricing-aws-eu-west-1.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	r := NewResolver(dir, &http.Client{})
	r.fetch = func(_ context.Context, _ *http.Client, string2 string) (*Catalog, error) {
		return nil, errors.New("no network in test")
	}
	if _, ok := r.Rate(context.Background(), "eu-west-1", "m5.large"); ok {
		t.Error("a mismatched cache file was accepted; every host in eu-west-1 would carry us-east-1 prices")
	}
}

// TestRegionNamesCannotTraverseThePath. The region arrives from telemetry, so
// it is attacker-influenced and must never become a file path.
func TestRegionNamesCannotTraverseThePath(t *testing.T) {
	for _, bad := range []string{
		"../../etc/passwd", "us-east-1/../../x", "..", "/absolute",
		"UPPER-1", "semi;colon", "space here", "", "nul\x00byte",
	} {
		if safeRegionName(bad) {
			t.Errorf("safeRegionName(%q) = true", bad)
		}
	}
	for _, ok := range []string{"us-east-1", "eu-west-2", "ap-southeast-3", "il-central-1"} {
		if !safeRegionName(ok) {
			t.Errorf("safeRegionName(%q) = false, but it is a real region", ok)
		}
	}

	r := NewResolver(t.TempDir(), &http.Client{})
	if p := r.cachePath("../escape"); p != "" {
		t.Errorf("cachePath returned %q for a traversal attempt", p)
	}
}

func TestPutRefusesAnEmptyCatalog(t *testing.T) {
	r := NewResolver("", &http.Client{})
	if err := r.Put(nil); err == nil {
		t.Error("Put(nil) was accepted")
	}
	if err := r.Put(&Catalog{Region: "us-east-1"}); err == nil {
		t.Error("a catalog with no rates was accepted; it would price everything at zero")
	}
}
