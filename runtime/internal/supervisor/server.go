package supervisor

import (
	"encoding/json"
	"net/http"

	"github.com/Divad1111/openvpn-web/internal/ipc"
)

// Handler exposes authenticated, read-only status and diagnostics. No write RPC
// exists in Phase 1: neither web users nor an authenticated agent may start VPN.
func Handler(i Inspector, secret []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			deny(w)
			return
		}
		reply(w, http.StatusOK, i.Inspect())
	})
	mux.HandleFunc("/v1/checks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			deny(w)
			return
		}
		status := i.Inspect()
		reply(w, http.StatusOK, map[string]any{
			"configPresent": status.ConfigPresent, "configSafe": status.ConfigSafe,
			"tunAvailable": status.TUNAvailable, "binaryAvailable": status.BinaryAvailable,
			"diagnostics": status.Diagnostics,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { deny(w) })
	return ipc.Authenticated(secret, mux)
}
func reply(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}
func deny(w http.ResponseWriter) {
	reply(w, http.StatusNotImplemented, map[string]string{"code": "NOT_IMPLEMENTED"})
}
