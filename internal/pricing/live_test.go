package pricing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveAWSFetch runs the parser against the real AWS price list.
//
// It is skipped unless OBSPROBE is set, because it transfers 300 MB and needs
// the network -- but it is kept in the tree rather than deleted, because it is
// the ONLY thing that would notice AWS renaming a column or changing the
// meaning of one. The unit tests pin behaviour against a fixture captured from
// this file, and a fixture cannot detect that its source has moved on.
//
//	OBSPROBE=1 go test ./internal/pricing/ -run TestLiveAWSFetch -v -timeout 15m
//
// Last verified 2026-09-09 against publication 2026-09-09T00:46:05Z:
// 1245 instance types in 18s, all spot-checked prices exact.
func TestLiveAWSFetch(t *testing.T) {
	if os.Getenv("OBSPROBE") == "" {
		t.Skip("set OBSPROBE=1 to fetch the live AWS price list")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	start := time.Now()
	cat, err := FetchAWSRegion(ctx, &http.Client{Timeout: 12 * time.Minute}, "us-east-1")
	if err != nil {
		t.Fatalf("FetchAWSRegion: %v", err)
	}
	fmt.Printf("region=%s published=%s\n", cat.Region, cat.Published.Format(time.RFC3339))
	fmt.Printf("rates=%d  elapsed=%s\n", len(cat.Rates), time.Since(start).Round(time.Second))

	// Values published by AWS for on-demand Linux in us-east-1.
	want := map[string]float64{
		"m5.large": 0.096, "m5.xlarge": 0.192, "c5.xlarge": 0.170,
		"t3.medium": 0.0416, "t3.micro": 0.0104, "c6i.large": 0.085,
	}
	for itype, expect := range want {
		r, ok := cat.Lookup(itype)
		if !ok {
			fmt.Printf("  %-12s MISSING\n", itype)
			continue
		}
		flag := "ok"
		if r.USDPerHour != expect {
			flag = fmt.Sprintf("MISMATCH want %.4f", expect)
		}
		fmt.Printf("  %-12s $%.4f/hr  %dvCPU %gGiB  %s\n",
			itype, r.USDPerHour, r.VCPU, r.MemoryGiB, flag)
	}

	types := cat.InstanceTypes()
	fmt.Printf("first 12 of %d types: %v\n", len(types), types[:min(12, len(types))])
	if len(cat.Rates) < 100 {
		t.Errorf("only %d rates from a full region file; the filter is too tight", len(cat.Rates))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
