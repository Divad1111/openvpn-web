package agent

import (
	"encoding/json"
	"net/http"

	"github.com/Divad1111/openvpn-web/internal/ipc"
)

type Server struct {
	WriteEnabled  bool
	RuntimeSocket string
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.deny(w)
			return
		}
		state := "UNKNOWN"
		if resp, err := ipc.Client(s.RuntimeSocket).Get("http://runtime/v1/status"); err == nil {
			var data struct {
				State string `json:"state"`
			}
			if resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&data) == nil {
				state = data.State
			}
			_ = resp.Body.Close()
		}
		jsonReply(w, http.StatusOK, map[string]any{"writeEnabled": s.WriteEnabled, "runtimeState": state, "phase": "PHASE_0_SCAFFOLD"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.deny(w)
			return
		}
		jsonReply(w, http.StatusNotImplemented, map[string]string{"code": "NOT_IMPLEMENTED"})
	})
	return mux
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
