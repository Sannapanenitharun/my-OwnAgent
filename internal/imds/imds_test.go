package imds

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/obsagent/observability-agent/internal/platform"
)

func TestLookupPrefersIMDSv2(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("token method = %s", r.Method)
		}
		_, _ = w.Write([]byte("tok-1"))
	})
	mux.HandleFunc("/latest/meta-data/instance-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-aws-ec2-metadata-token") != "tok-1" {
			t.Errorf("missing v2 token")
		}
		_, _ = w.Write([]byte("i-0abc123def4567890"))
	})
	mux.HandleFunc("/latest/meta-data/placement/availability-zone", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("us-east-1a"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := (&Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).Lookup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceID != "i-0abc123def4567890" {
		t.Fatalf("instance id = %q", got.InstanceID)
	}
	if got.AZ != "us-east-1a" {
		t.Fatalf("az = %q", got.AZ)
	}
}

func TestLookupDoesNotInventWhenUnreachable(t *testing.T) {
	c := &Client{
		BaseURL:    "http://127.0.0.1:1",
		HTTPClient: &http.Client{},
	}
	_, err := c.LookupInstanceID(context.Background())
	if !errors.Is(err, platform.ErrUnresolved) {
		t.Fatalf("err = %v, want ErrUnresolved", err)
	}
}

func TestLookupRejectsNonInstanceID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tok"))
	})
	mux.HandleFunc("/latest/meta-data/instance-id", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ip-10-0-0-1"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := (&Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).LookupInstanceID(context.Background())
	if !errors.Is(err, platform.ErrUnresolved) {
		t.Fatalf("err = %v, want ErrUnresolved (must not accept a hostname as instance id)", err)
	}
}

func TestResolveHostIDPrefersExplicit(t *testing.T) {
	got := ResolveHostID(context.Background(), "host-from-env", &Client{BaseURL: "http://127.0.0.1:1"})
	if got != "host-from-env" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveHostIDUsesIMDSWhenUnset(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tok"))
	})
	mux.HandleFunc("/latest/meta-data/instance-id", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("i-0123456789abcdef0"))
	})
	mux.HandleFunc("/latest/meta-data/placement/availability-zone", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("us-east-1a"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got := ResolveHostID(context.Background(), "", &Client{BaseURL: srv.URL, HTTPClient: srv.Client()})
	if got != "i-0123456789abcdef0" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveHostIDEmptyWhenNotOnEC2(t *testing.T) {
	got := ResolveHostID(context.Background(), "  ", &Client{BaseURL: "http://127.0.0.1:1"})
	if got != "" {
		t.Fatalf("invented host id %q", got)
	}
}

func TestLookupFillsResourceFields(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tok"))
	})
	mux.HandleFunc("/latest/meta-data/instance-id", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("i-0abc123def4567890"))
	})
	mux.HandleFunc("/latest/meta-data/placement/availability-zone", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("us-west-2b"))
	})
	mux.HandleFunc("/latest/meta-data/placement/region", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("us-west-2"))
	})
	mux.HandleFunc("/latest/meta-data/instance-type", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("t3.micro"))
	})
	mux.HandleFunc("/latest/meta-data/ami-id", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ami-0123456789abcdef0"))
	})
	mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"accountId":"123456789012","region":"us-west-2","imageId":"ami-0123456789abcdef0","instanceType":"t3.micro"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := (&Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).Lookup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != "123456789012" || got.Region != "us-west-2" || got.InstanceType != "t3.micro" || got.AMIID != "ami-0123456789abcdef0" {
		t.Fatalf("identity = %+v", got)
	}
	attrs := got.ResourceAttributes()
	keys := map[string]string{}
	for _, a := range attrs {
		keys[a.Key] = a.Value
	}
	if keys["host.id"] != "i-0abc123def4567890" || keys["cloud.provider"] != "aws" || keys["cloud.account.id"] != "123456789012" {
		t.Fatalf("resource attrs = %v", keys)
	}
}

func TestLookupRejectsInventedAccountID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tok"))
	})
	mux.HandleFunc("/latest/meta-data/instance-id", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("i-0abc123def4567890"))
	})
	mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"accountId":"not-an-account"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	got, err := (&Client{BaseURL: srv.URL, HTTPClient: srv.Client()}).Lookup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.AccountID != "" {
		t.Fatalf("accepted invalid account id %q", got.AccountID)
	}
}

func TestResourceAttributesOmitUnresolved(t *testing.T) {
	attrs := Identity{}.ResourceAttributes()
	if len(attrs) != 0 {
		t.Fatalf("empty identity produced %v", attrs)
	}
}
