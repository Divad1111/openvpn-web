package manager

import (
	"encoding/json"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestAllWritesFailClosed(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := Server{WriteEnabled: enabled, AgentSocket: "/tmp/does-not-exist", WebDir: t.TempDir()}
		for _, path := range []string{"/api/v1/setup/admin", "/api/v1/clients", "/api/v1/vpn/start", "/api/v1/backups"} {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			res := httptest.NewRecorder()
			s.Handler().ServeHTTP(res, req)
			if res.Code < 400 {
				t.Fatalf("enabled=%v path=%s returned %d", enabled, path, res.Code)
			}
			if !enabled && res.Code != http.StatusLocked {
				t.Fatalf("expected 423 for read-only, got %d", res.Code)
			}
		}
	}
}
func TestFailClosedWithoutAgent(t *testing.T) {
	s := Server{WriteEnabled: true, AgentSocket: "/tmp/nonexistent", WebDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	res := httptest.NewRecorder()
	s.Handler().ServeHTTP(res, req)
	var body struct {
		EffectiveWriteAllowed bool `json:"effectiveWriteAllowed"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.EffectiveWriteAllowed {
		t.Fatal("cannot allow writes when agent is unreachable")
	}
}

func TestManagerFetchesSignedAgentStatus(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "manager.key")
	key, err := ipc.EnsureKey(keyPath, -1)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "agent.sock")
	listener, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: ipc.Authenticated(key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"phase":"PHASE_1_AUTHENTICATED_IPC","writeEnabled":true,"runtimeAvailable":true,"runtimeState":"UNINITIALIZED","runtimeStatus":{"diagnostics":["No config"],"tunAvailable":true}}`))
	}))}
	go srv.Serve(listener)
	defer func() { _ = srv.Close(); _ = listener.Close() }()
	m := Server{WriteEnabled: true, AgentSocket: socket, AgentKeyPath: keyPath, WebDir: dir}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var v struct {
		EffectiveWriteAllowed bool   `json:"effectiveWriteAllowed"`
		RuntimeState          string `json:"runtimeState"`
		RuntimeAvailable      bool   `json:"runtimeAvailable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if !v.EffectiveWriteAllowed || v.RuntimeState != "UNINITIALIZED" || !v.RuntimeAvailable {
		t.Fatalf("wrong status %+v", v)
	}
	m.AgentKeyPath = filepath.Join(dir, "wrong.key")
	rec = httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.EffectiveWriteAllowed {
		t.Fatal("write permission must fail closed when signed IPC unavailable")
	}
}
