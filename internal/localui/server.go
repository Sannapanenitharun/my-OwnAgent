package localui

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/obsagent/observability-agent/internal/diagnostics"
	"github.com/obsagent/observability-agent/internal/platform"
	"github.com/obsagent/observability-agent/internal/supervisor"
)

//go:embed ui.html
var uiHTML []byte

// Server serves the local status UI for one agent process.
type Server struct {
	Identity    platform.Identity
	Telemetry   platform.Telemetry
	Supervisor  *supervisor.Supervisor
	Diagnostics *diagnostics.Recorder
}

// Handler returns the mux. Bind it to localhost.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleUI)
	mux.HandleFunc("/api/status", s.handleStatus)
	return mux
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(uiHTML)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := BuildStatus(r.Context(), s.Identity, s.Telemetry, s.Supervisor, s.Diagnostics)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// AddrEnabled reports whether the listen address should start a server.
// "off", "-", and empty disable the UI.
func AddrEnabled(addr string) bool {
	a := strings.TrimSpace(strings.ToLower(addr))
	return a != "" && a != "off" && a != "-" && a != "false"
}
