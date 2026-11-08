package supervisor

import (
	"encoding/json"
	"net/http"
)

// Phase 0 does not start OpenVPN. This is intentional: no PKI/configuration
// has been provisioned and there are no authenticated mutation RPCs yet.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			deny(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"state": "UNINITIALIZED", "phase": "PHASE_0_SCAFFOLD", "running": false})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		deny(w)
	})
	return mux
}
func deny(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"code":"NOT_IMPLEMENTED"}`))
}
