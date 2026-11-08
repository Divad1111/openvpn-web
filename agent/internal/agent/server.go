package agent

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/Divad1111/openvpn-web/internal/ipc"
)

type Server struct {
	WriteEnabled   bool
	RuntimeSocket  string
	RuntimeKeyPath string
}

type runtimeStatus struct {
	State           string   `json:"state"`
	Phase           string   `json:"phase"`
	Running         bool     `json:"running"`
	ConfigPresent   bool     `json:"configPresent"`
	ConfigSafe      bool     `json:"configSafe"`
	TUNAvailable    bool     `json:"tunAvailable"`
	BinaryAvailable bool     `json:"binaryAvailable"`
	Diagnostics     []string `json:"diagnostics"`
}

func (s Server) Handler(agentKey []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.deny(w)
			return
		}
		state := "UNKNOWN"
		reachable := false
		var status runtimeStatus
		if data, err := s.readRuntime(); err == nil {
			reachable = true
			status = data
			state = data.State
		}
		jsonReply(w, http.StatusOK, map[string]any{
			"writeEnabled": s.WriteEnabled,
			"runtimeState": state, "runtimeAvailable": reachable,
			"runtimeStatus": status,
			"phase":         "PHASE_1_AUTHENTICATED_IPC",
		})
	})
	mux.HandleFunc("/v1/checks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.deny(w)
			return
		}
		data, err := s.readRuntime()
		if err != nil {
			jsonReply(w, http.StatusServiceUnavailable, map[string]string{"code": "RUNTIME_UNAVAILABLE"})
			return
		}
		jsonReply(w, http.StatusOK, map[string]any{
			"configPresent": data.ConfigPresent, "configSafe": data.ConfigSafe,
			"tunAvailable": data.TUNAvailable, "binaryAvailable": data.BinaryAvailable,
			"diagnostics": data.Diagnostics,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.deny(w)
			return
		}
		jsonReply(w, http.StatusNotImplemented, map[string]string{"code": "NOT_IMPLEMENTED"})
	})
	return ipc.Authenticated(agentKey, mux)
}

func (s Server) readRuntime() (runtimeStatus, error) {
	var data runtimeStatus
	resp, err := ipc.SignedClient(s.RuntimeSocket, s.RuntimeKeyPath).Get("http://runtime/v1/status")
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return data, os.ErrPermission
	}
	if err = json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return data, err
	}
	if data.State == "" {
		return data, os.ErrInvalid
	}
	return data, nil
}
func (s Server) deny(w http.ResponseWriter) {
	if !s.WriteEnabled {
		jsonReply(w, http.StatusLocked, map[string]string{"code": "WRITE_MODE_DISABLED"})
		return
	}
	jsonReply(w, http.StatusNotImplemented, map[string]string{"code": "NOT_IMPLEMENTED"})
}
func jsonReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
