package manager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/internal/security"
)

func newAuthAndFakeAgent(t *testing.T, agentWrite bool) (*Auth, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	a, err := OpenAuth(filepath.Join(dir, "db.sqlite"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	bootstrap, err := a.EnsureBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	keypath := filepath.Join(dir, "ipc.key")
	key, err := ipc.EnsureKey(keypath, -1)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "agent.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	phase := "PHASE_3_VPN_API"
	state := "UNINITIALIZED"
	handler := ipc.Authenticated(key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"writeEnabled": agentWrite, "phase": phase, "runtimeState": state, "runtimeAvailable": true})
	}))
	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	t.Cleanup(func() { _ = srv.Close(); _ = l.Close() })
	return a, bootstrap, sock, keypath
}
func doRequest(h http.Handler, method, path string, body any, token, csrf string) *httptest.ResponseRecorder {
	var src *bytes.Reader
	if body == nil {
		src = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		src = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, "https://127.0.0.1:9443"+path, src)
	r.Header.Set("Origin", "https://127.0.0.1:9443")
	r.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if token != "" {
		r.AddCookie(&http.Cookie{Name: "ovpn_session", Value: token})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestBootstrapRequiresBothDockerFlags(t *testing.T) {
	for _, pair := range [][2]bool{{false, false}, {false, true}, {true, false}} {
		a, token, sock, key := newAuthAndFakeAgent(t, pair[1])
		app := &App{Auth: a, WriteEnabled: pair[0], AgentSocket: sock, AgentKeyPath: key, WebDir: t.TempDir()}
		r := doRequest(app.Handler(), "POST", "/api/v1/setup/start", map[string]string{"token": token, "username": "admin", "password": "some-very-strong-password"}, "", "")
		if r.Code != 423 {
			t.Fatalf("manager=%v agent=%v returned %d body=%s", pair[0], pair[1], r.Code, r.Body.String())
		}
	}
}
func TestBootSetupTOTPLoginAndCSRF(t *testing.T) {
	a, token, sock, key := newAuthAndFakeAgent(t, true)
	app := &App{Auth: a, WriteEnabled: true, AgentSocket: sock, AgentKeyPath: key, WebDir: t.TempDir()}
	h := app.Handler()
	req := map[string]string{"token": token, "username": "admin", "password": "some-very-strong-password"}
	resp := doRequest(h, "POST", "/api/v1/setup/start", req, "", "")
	if resp.Code != 200 {
		t.Fatalf("bootstrap: %d %s", resp.Code, resp.Body.String())
	}
	var result map[string]string
	if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(result["totpURI"])
	if err != nil {
		t.Fatal(err)
	}
	secret := uri.Query().Get("secret")
	otp, _ := security.OTP(secret, time.Now().Unix()/30)
	resp = doRequest(h, "POST", "/api/v1/setup/finish", map[string]string{"challenge": result["challenge"], "otp": otp}, "", "")
	if resp.Code != 200 || !a.AdminReady() {
		t.Fatalf("finish: %d %s", resp.Code, resp.Body.String())
	}
	resp = doRequest(h, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "some-very-strong-password", "otp": otp}, "", "")
	if resp.Code != 200 {
		t.Fatalf("login: %d %s", resp.Code, resp.Body.String())
	}
	cookie := resp.Result().Cookies()[0].Value
	if !resp.Result().Cookies()[0].Secure || !resp.Result().Cookies()[0].HttpOnly {
		t.Fatal("unsafe session cookie")
	}
	resp = doRequest(h, "POST", "/api/v1/vpn/stop", map[string]string{"totp": otp}, cookie, "wrong-csrf")
	if resp.Code != 403 {
		t.Fatalf("CSRF bypass: %d", resp.Code)
	}
	resp = doRequest(h, "GET", "/api/v1/audit", nil, cookie, "")
	if resp.Code != 200 || !strings.Contains(resp.Body.String(), "login") {
		t.Fatalf("audit: %d %s", resp.Code, resp.Body.String())
	}
	resp = doRequest(h, "POST", "/api/v1/setup/start", req, "", "")
	if resp.Code != 409 {
		t.Fatalf("bootstrap replay: %d", resp.Code)
	}
}
