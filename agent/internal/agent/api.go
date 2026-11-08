package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Divad1111/openvpn-web/agent/internal/engine"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type API struct {
	WriteEnabled bool
	Engine       *engine.Engine
}

func (a *API) Handler(secret []byte) http.Handler {
	mux := http.NewServeMux()
	send := func(w http.ResponseWriter, code int, data any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(data)
	}
	deny := func(w http.ResponseWriter) {
		if !a.WriteEnabled {
			send(w, 423, map[string]string{"code": "WRITE_MODE_DISABLED"})
		} else {
			send(w, 404, map[string]string{"code": "UNKNOWN_OPERATION"})
		}
	}
	fail := func(w http.ResponseWriter, err error) {
		send(w, 409, map[string]string{"code": "OPERATION_FAILED", "message": safeError(err)})
	}
	decode := func(w http.ResponseWriter, r *http.Request, v any) bool {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 60*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			send(w, 400, map[string]string{"code": "INVALID_REQUEST"})
			return false
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			send(w, 400, map[string]string{"code": "TRAILING_JSON"})
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		raw, code, err := a.Engine.RuntimeCall(http.MethodGet, "/v1/status", nil)
		st := runtimeStatus{}
		if err == nil && code == 200 {
			_ = json.Unmarshal(raw, &st)
		}
		send(w, 200, map[string]any{"writeEnabled": a.WriteEnabled, "runtimeState": func() string {
			if st.State == "" {
				return "UNKNOWN"
			}
			return st.State
		}(), "runtimeAvailable": err == nil && code == 200, "runtimeStatus": st, "phase": "PHASE_3_VPN_API", "pkiReady": a.Engine.PKIReady(), "revision": a.Engine.Revision()})
	})
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		c, err := a.Engine.Config()
		if err != nil {
			send(w, 200, map[string]any{"configured": false})
			return
		}
		render, _ := engine.Render(c)
		send(w, 200, map[string]any{"configured": true, "config": c, "rendered": render, "revision": a.Engine.Revision()})
	})
	mux.HandleFunc("GET /v1/clients", func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.Engine.Clients()
		if err != nil {
			fail(w, err)
			return
		}
		send(w, 200, map[string]any{"clients": rows})
	})
	mux.HandleFunc("GET /v1/connections", func(w http.ResponseWriter, r *http.Request) {
		raw, code, err := a.Engine.RuntimeCall(http.MethodGet, "/v1/connections", nil)
		if err != nil || code != 200 {
			send(w, 503, map[string]string{"code": "RUNTIME_UNAVAILABLE"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(raw)
	})
	mux.HandleFunc("GET /v1/backups", func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.Engine.Backups()
		if err != nil {
			fail(w, err)
			return
		}
		send(w, 200, map[string]any{"revisions": rows, "backupSupported": true, "restoreSupported": false})
	})
	// Backup ciphertext is exported into a volume readable by Manager; the
	// Agent's CA key volume is never directly accessible to Manager.
	mux.HandleFunc("POST /v1/config/validate", func(w http.ResponseWriter, r *http.Request) {
		var c engine.Config
		if !decode(w, r, &c) {
			return
		}
		config, err := engine.Render(c)
		if err != nil {
			send(w, 400, map[string]string{"code": "INVALID_CONFIG", "message": err.Error()})
			return
		}
		send(w, 200, map[string]string{"serverConfig": config, "message": "Validation is static; runtime preflight occurs during apply"})
	})
	// One policy boundary in the Agent for *every* state-changing route.
	guarded := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !a.WriteEnabled {
				send(w, 423, map[string]string{"code": "WRITE_MODE_DISABLED"})
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("POST /v1/backups", guarded(func(w http.ResponseWriter, r *http.Request) {
		var input struct{ ID, Passphrase string }
		if !decode(w, r, &input) {
			return
		}
		meta, err := a.Engine.CreateEncryptedBackup(input.ID, input.Passphrase, getenvExport())
		if err != nil {
			fail(w, err)
			return
		}
		send(w, 201, meta)
	}))
	mux.HandleFunc("POST /v1/backups/{id}/validate", guarded(func(w http.ResponseWriter, r *http.Request) {
		var input struct{ Passphrase string }
		if !decode(w, r, &input) {
			return
		}
		result, err := a.Engine.ValidateEncryptedBackup(r.PathValue("id"), input.Passphrase, getenvExport())
		if err != nil {
			fail(w, err)
			return
		}
		send(w, 200, result)
	}))
	mux.HandleFunc("POST /v1/pki/init", guarded(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Passphrase string `json:"passphrase"`
		}
		if !decode(w, r, &v) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := a.Engine.InitPKI(ctx, v.Passphrase); err != nil {
			fail(w, err)
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /v1/config/apply", guarded(func(w http.ResponseWriter, r *http.Request) {
		var v engine.Config
		if !decode(w, r, &v) {
			return
		}
		if err := a.Engine.ApplyConfig(v); err != nil {
			fail(w, err)
			return
		}
		send(w, 200, map[string]any{"ok": true, "revision": a.Engine.Revision()})
	}))
	mux.HandleFunc("POST /v1/clients", guarded(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Name, Passphrase string
			Days             int
		}
		if !decode(w, r, &v) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		item, err := a.Engine.CreateClient(ctx, v.Name, v.Passphrase, v.Days)
		if err != nil {
			fail(w, err)
			return
		}
		send(w, 201, item)
	}))
	mux.HandleFunc("POST /v1/clients/{id}/export", guarded(func(w http.ResponseWriter, r *http.Request) {
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		profile, err := a.Engine.ExportClient(r.PathValue("id"))
		if err != nil {
			fail(w, err)
			return
		}
		send(w, 200, map[string]string{"ovpn": profile, "filename": "client.ovpn"})
	}))
	mux.HandleFunc("POST /v1/clients/{id}/revoke", guarded(func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Passphrase string }
		if !decode(w, r, &v) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
		defer cancel()
		if err := a.Engine.RevokeClient(ctx, r.PathValue("id"), v.Passphrase); err != nil {
			fail(w, err)
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
	for _, operation := range []string{"start", "stop", "reload"} {
		op := operation
		mux.HandleFunc("POST /v1/runtime/"+op, guarded(func(w http.ResponseWriter, r *http.Request) {
			var v struct{}
			if !decode(w, r, &v) {
				return
			}
			_, code, err := a.Engine.RuntimeCall(http.MethodPost, "/v1/"+op, nil)
			if err != nil || code != 200 {
				send(w, 409, map[string]string{"code": "RUNTIME_OPERATION_FAILED"})
				return
			}
			send(w, 200, map[string]bool{"ok": true})
		}))
	}
	mux.HandleFunc("POST /v1/connections/{id}/disconnect", guarded(func(w http.ResponseWriter, r *http.Request) {
		var v struct{}
		if !decode(w, r, &v) {
			return
		}
		id := r.PathValue("id")
		if _, code, err := a.Engine.RuntimeCall(http.MethodPost, "/v1/kick", map[string]string{"commonName": id}); err != nil || code != 200 {
			send(w, 409, map[string]string{"code": "KICK_FAILED"})
			return
		}
		send(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { deny(w) })
	return ipc.Authenticated(secret, mux)
}
func safeError(err error) string {
	if err == nil {
		return ""
	}
	// Never return OpenSSL/EasyRSA output or system paths to a remote browser.
	msg := err.Error()
	for _, p := range []string{"/data/", "/etc/", "/run/"} {
		if strings.Contains(msg, p) {
			return "Operation failed. Consult sanitized server audit logs."
		}
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}

var _ = errors.New

func getenvExport() string {
	if val := os.Getenv("AGENT_BACKUP_EXPORT_DIR"); val != "" {
		return val
	}
	return "/data/export"
}
