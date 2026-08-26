package fleet

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed fleet.html
var fleetHTML []byte

// Server exposes the fleet view over HTTP. Bind it to localhost unless the
// intake is deliberately reachable: the page shows every host reporting in.
type Server struct {
	Store *Store
}

// Handler returns the mux for the fleet UI and its JSON API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/fleet", s.handleFleet)
	mux.HandleFunc("/api/host", s.handleHost)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(fleetHTML)
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.Fleet())
}

func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("host"))
	if name == "" {
		http.Error(w, "host query parameter is required", http.StatusBadRequest)
		return
	}
	detail, ok := s.Store.Host(name)
	if !ok {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	writeJSON(w, detail)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// AddrEnabled reports whether a listen address should start a server.
// "off", "-", "false", and empty disable it.
func AddrEnabled(addr string) bool {
	a := strings.TrimSpace(strings.ToLower(addr))
	return a != "" && a != "off" && a != "-" && a != "false"
}
