package manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/internal/policy"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type App struct {
	Auth                              *Auth
	WriteEnabled                      bool
	AgentSocket, AgentKeyPath, WebDir string
}

func (a *App) agentStatus() (agentStatus, error) {
	var st agentStatus
	response, err := ipc.SignedClient(a.AgentSocket, a.AgentKeyPath).Get("http://agent/v1/status")
	if err != nil {
		return st, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return st, errors.New("agent status failure")
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&st); err != nil {
		return st, err
	}
	// Avoid accepting an uninitialized / malformed Agent response as permission.
	if st.Phase == "" {
		return st, errors.New("missing agent phase")
	}
	return st, nil
}
func (a *App) writable() error {
	if !a.WriteEnabled {
		return errors.New("WRITE_MODE_DISABLED")
	}
	st, err := a.agentStatus()
	if err != nil {
		return errors.New("AGENT_UNAVAILABLE")
	}
	if !policy.EffectiveWriteMode(a.WriteEnabled, st.WriteEnabled) {
		return errors.New("WRITE_MODE_MISMATCH")
	}
	return nil
}
func (a *App) callAgent(method, path string, data any) (json.RawMessage, int, error) {
	var body io.Reader
	if data != nil {
		v, err := json.Marshal(data)
		if err != nil {
			return nil, 0, err
		}
		if len(v) > 60*1024 {
			return nil, 0, errors.New("payload too large")
		}
		body = bytes.NewReader(v)
	}
	req, err := http.NewRequest(method, "http://agent"+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := ipc.SignedClient(a.AgentSocket, a.AgentKeyPath)
	client.Timeout = 95 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return raw, resp.StatusCode, err
}
func rejectCode(w http.ResponseWriter, code string) {
	status := http.StatusBadRequest
	switch code {
	case "WRITE_MODE_DISABLED", "WRITE_MODE_MISMATCH":
		status = http.StatusLocked
	case "AGENT_UNAVAILABLE":
		status = http.StatusServiceUnavailable
	case "AUTH_REQUIRED":
		status = http.StatusUnauthorized
	case "FORBIDDEN", "TOTP_REQUIRED":
		status = http.StatusForbidden
	case "NOT_IMPLEMENTED":
		status = http.StatusNotImplemented
	case "UNINITIALIZED", "CONFLICT":
		status = http.StatusConflict
	}
	respondError(w, status, code, code)
}
func requireOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("X-CSRF-Token") != ""
	} // CLI clients require CSRF; bootstrap uses Origin.
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "https" && strings.EqualFold(parsed.Host, r.Host)
}
func ipOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]string{"status": "ok", "component": "manager"})
	})
	mux.HandleFunc("GET /api/v1/meta", func(w http.ResponseWriter, r *http.Request) {
		st, err := a.agentStatus()
		allowed := err == nil && policy.EffectiveWriteMode(a.WriteEnabled, st.WriteEnabled)
		state := "UNKNOWN"
		if err == nil {
			state = st.RuntimeState
		}
		respond(w, 200, map[string]any{"openvpnVersion": "2.7.9", "phase": "PHASE_2_PLUS", "managerWriteEnabled": a.WriteEnabled, "agentWriteEnabled": err == nil && st.WriteEnabled, "agentAvailable": err == nil, "effectiveWriteAllowed": allowed, "runtimeAvailable": err == nil && st.RuntimeAvailable, "runtimeState": state, "setupAvailable": !a.Auth.AdminReady() && allowed, "initialized": a.Auth.AdminReady()})
	})
	mux.HandleFunc("GET /api/v1/setup/state", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"initialized": a.Auth.AdminReady(), "writeEnabled": a.writable() == nil, "requiresBootstrap": !a.Auth.AdminReady()})
	})
	mux.HandleFunc("POST /api/v1/setup/start", func(w http.ResponseWriter, r *http.Request) {
		if a.Auth.AdminReady() {
			rejectCode(w, "CONFLICT")
			return
		}
		if err := a.writable(); err != nil {
			rejectCode(w, err.Error())
			return
		}
		if r.Header.Get("Origin") == "" || !requireOrigin(r) {
			rejectCode(w, "FORBIDDEN")
			return
		}
		var v struct{ Token, Username, Password string }
		if readJSON(r, &v) != nil {
			rejectCode(w, "INVALID_REQUEST")
			return
		}
		id, uri, err := a.Auth.BeginSetup(v.Token, v.Username, v.Password, ipOf(r))
		if err != nil {
			rejectCode(w, "FORBIDDEN")
			return
		}
		respond(w, 200, map[string]string{"challenge": id, "totpURI": uri})
	})
	mux.HandleFunc("POST /api/v1/setup/finish", func(w http.ResponseWriter, r *http.Request) {
		if err := a.writable(); err != nil {
			rejectCode(w, err.Error())
			return
		}
		if r.Header.Get("Origin") == "" || !requireOrigin(r) {
			rejectCode(w, "FORBIDDEN")
			return
		}
		var v struct{ Challenge, OTP string }
		if readJSON(r, &v) != nil {
			rejectCode(w, "INVALID_REQUEST")
			return
		}
		user, err := a.Auth.FinishSetup(v.Challenge, v.OTP, ipOf(r))
		if err != nil {
			rejectCode(w, "FORBIDDEN")
			return
		}
		respond(w, 200, map[string]any{"initialized": true, "username": user})
	})
	mux.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "" || !requireOrigin(r) {
			rejectCode(w, "FORBIDDEN")
			return
		}
		var v struct{ Username, Password, OTP string }
		if readJSON(r, &v) != nil {
			rejectCode(w, "INVALID_REQUEST")
			return
		}
		token, sess, err := a.Auth.Login(v.Username, v.Password, v.OTP, ipOf(r))
		if err != nil {
			rejectCode(w, "AUTH_REQUIRED")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "ovpn_session", Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Expires: sess.Expires, MaxAge: int(sessionLifetime.Seconds())})
		respond(w, 200, map[string]any{"username": sess.Username, "csrfToken": sess.CSRF})
	})
	// All remaining /api/v1 routes require authentication. No unauthenticated
	// write, export, WebSocket, status or setup API is delegated to Agent.
	mux.Handle("/api/v1/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("ovpn_session")
		if err != nil {
			rejectCode(w, "AUTH_REQUIRED")
			return
		}
		sess, ok := a.Auth.Check(cookie.Value)
		if !ok {
			rejectCode(w, "AUTH_REQUIRED")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !requireOrigin(r) || !a.Auth.CheckCSRF(sess, r.Header.Get("X-CSRF-Token")) {
				rejectCode(w, "FORBIDDEN")
				return
			}
		}
		switch {
		case r.URL.Path == "/api/v1/auth/me" && r.Method == http.MethodGet:
			token, err := a.Auth.RefreshCSRF(sess)
			if err != nil {
				rejectCode(w, "AGENT_UNAVAILABLE")
				return
			}
			respond(w, 200, map[string]string{"username": sess.Username, "csrfToken": token})
			return
		case r.URL.Path == "/api/v1/auth/logout" && r.Method == http.MethodPost:
			_ = a.Auth.Logout(sess)
			http.SetCookie(w, &http.Cookie{Name: "ovpn_session", Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
			respond(w, 200, map[string]bool{"ok": true})
			return
		case r.URL.Path == "/api/v1/audit" && r.Method == http.MethodGet:
			logs, err := a.Auth.Audits()
			if err != nil {
				rejectCode(w, "AGENT_UNAVAILABLE")
				return
			}
			respond(w, 200, map[string]any{"entries": logs})
			return
		}
		// Explicit fixed-operation routing. No arbitrary forwarding of user paths.
		routes := map[string]string{"/api/v1/vpn/status": "/v1/status", "/api/v1/vpn/config": "/v1/config", "/api/v1/clients": "/v1/clients", "/api/v1/connections": "/v1/connections", "/api/v1/backups": "/v1/backups"}
		if r.Method == http.MethodGet {
			if dest, ok := routes[r.URL.Path]; ok {
				a.proxy(w, r, dest, nil)
				return
			}
		}
		if r.Method == http.MethodPost {
			action := r.URL.Path
			dest := ""
			sensitive := false
			switch action {
			case "/api/v1/setup/pki":
				dest = "/v1/pki/init"
				sensitive = true
			case "/api/v1/setup/complete":
				dest = "/v1/config/apply"
				sensitive = true
			case "/api/v1/vpn/config/apply":
				dest = "/v1/config/apply"
				sensitive = true
			case "/api/v1/vpn/start":
				dest = "/v1/runtime/start"
			case "/api/v1/vpn/stop":
				dest = "/v1/runtime/stop"
				sensitive = true
			case "/api/v1/vpn/reload":
				dest = "/v1/runtime/reload"
			case "/api/v1/clients":
				dest = "/v1/clients"
				sensitive = true
			case "/api/v1/backups":
				dest = "/v1/backups"
				sensitive = true
			case "/api/v1/vpn/config/validate":
				a.preview(w, r)
				return
			default:
				if id, verb, ok := parseResource(action, "/api/v1/clients/"); ok && verb == "revoke" {
					dest = "/v1/clients/" + id + "/revoke"
					sensitive = true
				} else if ok && verb == "export" {
					dest = "/v1/clients/" + id + "/export"
					sensitive = true
				} else if id, verb, ok := parseResource(action, "/api/v1/connections/"); ok && verb == "disconnect" {
					dest = "/v1/connections/" + id + "/disconnect"
				}
			}
			if dest != "" {
				if err := a.writable(); err != nil {
					rejectCode(w, err.Error())
					return
				}
				var body map[string]any
				if readJSON(r, &body) != nil {
					rejectCode(w, "INVALID_REQUEST")
					return
				}
				if sensitive {
					code, _ := body["totp"].(string)
					if code == "" {
						rejectCode(w, "TOTP_REQUIRED")
						return
					}
					if !a.verifyAdminTOTP(sess.Username, code) {
						rejectCode(w, "TOTP_REQUIRED")
						return
					}
					delete(body, "totp")
				}
				a.Auth.Audit(sess.Username, action, ipOf(r), "requested", "")
				a.proxy(w, r, dest, body)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !a.WriteEnabled {
				rejectCode(w, "WRITE_MODE_DISABLED")
				return
			}
		}
		rejectCode(w, "NOT_IMPLEMENTED")
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			rejectCode(w, "FORBIDDEN")
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)
		name := filepath.Join(a.WebDir, strings.TrimPrefix(clean, "/"))
		if !strings.HasPrefix(name, filepath.Clean(a.WebDir)+string(os.PathSeparator)) && name != filepath.Clean(a.WebDir) {
			http.NotFound(w, r)
			return
		}
		st, err := os.Stat(name)
		if err != nil || st.IsDir() {
			name = filepath.Join(a.WebDir, "index.html")
		}
		http.ServeFile(w, r, name)
	})
	return securityHeaders(mux)
}
func parseResource(path, prefix string) (string, string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	if !valid.MatchString(parts[0]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) verifyAdminTOTP(username, code string) bool {
	return a.Auth.VerifyAdminTOTP(username, code)
}
func (a *App) proxy(w http.ResponseWriter, r *http.Request, path string, body any) {
	raw, status, err := a.callAgent(r.Method, path, body)
	if err != nil {
		rejectCode(w, "AGENT_UNAVAILABLE")
		return
	}
	if status < 200 || status >= 300 {
		a.Auth.Audit("manager", r.URL.Path, ipOf(r), "failed", fmt.Sprintf("status=%d", status))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}
func (a *App) preview(w http.ResponseWriter, r *http.Request) {
	var v map[string]any
	if readJSON(r, &v) != nil {
		rejectCode(w, "INVALID_REQUEST")
		return
	}
	raw, status, err := a.callAgent("POST", "/v1/config/validate", v)
	if err != nil {
		rejectCode(w, "AGENT_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}
