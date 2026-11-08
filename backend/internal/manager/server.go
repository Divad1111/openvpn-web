package manager

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/internal/policy"
)

type Server struct {
	WriteEnabled bool
	AgentSocket  string
	WebDir       string
}
type agentStatus struct {
	WriteEnabled bool   `json:"writeEnabled"`
	RuntimeState string `json:"runtimeState"`
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/meta", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		a, err := s.readAgent()
		allowed := policy.EffectiveWriteMode(s.WriteEnabled, err == nil && a.WriteEnabled)
		runtimeState := "UNKNOWN"
		if err == nil {
			runtimeState = a.RuntimeState
		}
		respond(w, http.StatusOK, map[string]any{
			"phase": "PHASE_0_SCAFFOLD", "openvpnVersion": "2.7.9",
			"managerWriteEnabled":   s.WriteEnabled,
			"agentAvailable":        err == nil,
			"agentWriteEnabled":     err == nil && a.WriteEnabled,
			"effectiveWriteAllowed": allowed,
			"runtimeState":          runtimeState,
			"setupAvailable":        false,
			"message":               "Not yet deployable as a VPN server. Implementation Phase 0.",
		})
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		respond(w, http.StatusOK, map[string]string{"status": "ok", "component": "manager"})
	})
	// All operations are absent in Phase 0. Deny mutations regardless of URL,
	// even when the Docker write setting is true.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "API not implemented in Phase 0")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		name := filepath.Join(s.WebDir, strings.TrimPrefix(clean, "/"))
		if !strings.HasPrefix(name, filepath.Clean(s.WebDir)+string(os.PathSeparator)) && name != filepath.Clean(s.WebDir) {
			http.NotFound(w, r)
			return
		}
		st, err := os.Stat(name)
		if err != nil || st.IsDir() {
			name = filepath.Join(s.WebDir, "index.html")
		}
		http.ServeFile(w, r, name)
	})
	return mux
}

func (s Server) readAgent() (agentStatus, error) {
	var status agentStatus
	resp, err := ipc.Client(s.AgentSocket).Get("http://agent/v1/status")
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return status, os.ErrPermission
	}
	err = json.NewDecoder(resp.Body).Decode(&status)
	return status, err
}
func rejectWrite(w http.ResponseWriter, mode bool) {
	if !mode {
		respondError(w, http.StatusLocked, "WRITE_MODE_DISABLED", "Docker write mode disabled")
		return
	}
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "No mutation endpoints exist in Phase 0")
}
func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func respondError(w http.ResponseWriter, code int, reason, msg string) {
	respond(w, code, map[string]string{"code": reason, "message": msg})
}
