// Command obsagent-intake is a minimal HTTPS/HTTP sink for obsagent.v1
// payloads from the agent's native exporter.
//
// It is a development and demo backend, not a production Telemetry Plane.
// Run it, point export.native.endpoint at it, and watch batches arrive.
//
// Because every agent in a fleet ships here, the intake is also the only place
// that sees all of them at once. It therefore serves a fleet UI on a second
// listener: the agent's own :8181 page reports one host and cannot show more.
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/obsagent/observability-agent/internal/fleet"
)

const schema = "obsagent.v1"

type envelope struct {
	Schema    string            `json:"schema"`
	Signal    string            `json:"signal"`
	Timestamp string            `json:"timestamp"`
	Host      string            `json:"host,omitempty"`
	Resource  map[string]string `json:"resource,omitempty"`
	Logs      []json.RawMessage `json:"logs,omitempty"`
	Metrics   json.RawMessage   `json:"metrics,omitempty"`
	Spans     []json.RawMessage `json:"spans,omitempty"`
	Raw       []json.RawMessage `json:"raw,omitempty"`
	Events    []json.RawMessage `json:"events,omitempty"`
}

func main() {
	listen := flag.String("listen", envOr("INTAKE_LISTEN", "0.0.0.0:8080"), "listen address")
	apiKey := flag.String("api-key", os.Getenv("INTAKE_API_KEY"), "optional X-API-Key value; empty disables auth")
	dir := flag.String("store", "", "optional directory to append JSONL files (logs.jsonl, metrics.jsonl, traces.jsonl)")
	uiListen := flag.String("ui-listen", envOr("INTAKE_UI_LISTEN", "127.0.0.1:8181"), "fleet UI address; 'off' disables")
	flag.Parse()

	s := &server{
		apiKey: strings.TrimSpace(*apiKey),
		store:  strings.TrimSpace(*dir),
		fleet:  fleet.New(fleet.Limits{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", s.handle("logs"))
	mux.HandleFunc("/v1/metrics", s.handle("metrics"))
	mux.HandleFunc("/v1/traces", s.handle("traces"))
	mux.HandleFunc("/v1/inventory", s.handle("inventory"))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "obsagent-intake\nreceived logs=%d metrics=%d traces=%d\n",
			s.nLogs.Load(), s.nMetrics.Load(), s.nTraces.Load())
	})

	// The fleet UI runs on its own listener so ingest can be exposed to a
	// network while the UI stays on loopback, or the reverse.
	if fleet.AddrEnabled(*uiListen) {
		ui := &fleet.Server{Store: s.fleet}
		go func() {
			log.Printf("fleet UI listening on http://%s/", *uiListen)
			if err := http.ListenAndServe(*uiListen, ui.Handler()); err != nil {
				log.Fatalf("fleet UI: %v", err)
			}
		}()
	}

	log.Printf("obsagent-intake listening on http://%s (api-key auth %v)", *listen, *apiKey != "")
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	apiKey string
	store  string

	// fleet is the in-memory multi-host view the UI renders. It is bounded;
	// the JSONL archive on disk remains the complete record.
	fleet *fleet.Store

	mu         sync.Mutex
	nLogs      atomic.Int64
	nMetrics   atomic.Int64
	nTraces    atomic.Int64
	nInventory atomic.Int64
}

func (s *server) handle(signal string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if s.apiKey != "" && r.Header.Get("X-API-Key") != s.apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := readBody(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var env envelope
		if err := json.Unmarshal(body, &env); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if env.Schema != "" && env.Schema != schema {
			http.Error(w, "unsupported schema", http.StatusBadRequest)
			return
		}
		if env.Signal == "" {
			env.Signal = signal
		}
		switch signal {
		case "logs":
			s.nLogs.Add(1)
			log.Printf("logs host=%s n=%d ts=%s", env.Host, len(env.Logs), env.Timestamp)
		case "metrics":
			s.nMetrics.Add(1)
			log.Printf("metrics host=%s ts=%s", env.Host, env.Timestamp)
		case "traces":
			s.nTraces.Add(1)
			log.Printf("traces host=%s spans=%d raw=%d ts=%s", env.Host, len(env.Spans), len(env.Raw), env.Timestamp)
		case "inventory":
			s.nInventory.Add(1)
			log.Printf("inventory host=%s events=%d ts=%s", env.Host, len(env.Events), env.Timestamp)
		}
		// Fold into the fleet view before archiving: a parse failure here must
		// not stop the batch reaching disk.
		if s.fleet != nil {
			if err := s.fleet.Ingest(signal, body); err != nil {
				log.Printf("fleet: %v", err)
			}
		}
		if s.store != "" {
			if err := s.append(signal, body); err != nil {
				log.Printf("store: %v", err)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

func (s *server) append(signal string, body []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.store, 0o755); err != nil {
		return err
	}
	path := fmt.Sprintf("%s/%s.jsonl", strings.TrimRight(s.store, "/\\"), signal)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}

func readBody(r *http.Request) ([]byte, error) {
	var reader io.Reader = r.Body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		reader = zr
	}
	return io.ReadAll(io.LimitReader(reader, 8<<20))
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
