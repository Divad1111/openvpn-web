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
	AgentKeyPath string
	WebDir       string
}
type agentStatus struct {
	WriteEnabled     bool   `json:"writeEnabled"`
	RuntimeState     string `json:"runtimeState"`
	RuntimeAvailable bool   `json:"runtimeAvailable"`
	Phase            string `json:"phase"`
	RuntimeStatus    struct {
		Diagnostics     []string `json:"diagnostics"`
		TUNAvailable    bool     `json:"tunAvailable"`
		ConfigPresent   bool     `json:"configPresent"`
		ConfigSafe      bool     `json:"configSafe"`
		BinaryAvailable bool     `json:"binaryAvailable"`
	} `json:"runtimeStatus"`
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
		state := "UNKNOWN"
		if err == nil {
			state = a.RuntimeState
		}
		respond(w, http.StatusOK, map[string]any{
			"phase": "PHASE_1_AUTHENTICATED_IPC", "openvpnVersion": "2.7.9",
			"managerWriteEnabled": s.WriteEnabled, "agentAvailable": err == nil,
			"agentWriteEnabled": err == nil && a.WriteEnabled, "effectiveWriteAllowed": allowed,
			"runtimeState": state, "runtimeAvailable": err == nil && a.RuntimeAvailable,
			"runtimeDiagnostics": a.RuntimeStatus.Diagnostics, "setupAvailable": false,
			"message": "Phase 1: authenticated IPC & read-only diagnostics; VPN is not running.",
		})
	})
	mux.HandleFunc("/api/v1/system/checks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		a, err := s.readAgent()
		if err != nil || !a.RuntimeAvailable {
			respondError(w, http.StatusServiceUnavailable, "AGENT_OR_RUNTIME_UNAVAILABLE", "Authenticated internal service unavailable")
			return
		}
		respond(w, http.StatusOK, map[string]any{
			"tunAvailable":    a.RuntimeStatus.TUNAvailable,
			"binaryAvailable": a.RuntimeStatus.BinaryAvailable,
			"configPresent":   a.RuntimeStatus.ConfigPresent,
			"configSafe":      a.RuntimeStatus.ConfigSafe,
			"diagnostics":     a.RuntimeStatus.Diagnostics,
		})
	})
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		respond(w, http.StatusOK, map[string]string{"status": "ok", "component": "manager"})
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			rejectWrite(w, s.WriteEnabled)
			return
		}
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "API not implemented in Phase 1")
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
	var a agentStatus
	resp, err := ipc.SignedClient(s.AgentSocket, s.AgentKeyPath).Get("http://agent/v1/status")
	if err != nil {
		return a, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return a, os.ErrPermission
	}
	err = json.NewDecoder(resp.Body).Decode(&a)
	if err == nil && a.Phase != "PHASE_1_AUTHENTICATED_IPC" {
		return a, os.ErrInvalid
	}
	return a, err
}
func rejectWrite(w http.ResponseWriter, mode bool) {
	if !mode {
		respondError(w, http.StatusLocked, "WRITE_MODE_DISABLED", "Docker write mode disabled")
		return
	}
	respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "No mutation endpoints exist in Phase 1")
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
