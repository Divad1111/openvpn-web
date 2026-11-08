package agent

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Divad1111/openvpn-web/internal/ipc"
)

func TestUnauthenticatedRequestsDenied(t *testing.T) {
	key := make([]byte, 32)
	s := Server{WriteEnabled: false, RuntimeSocket: "/tmp/nowhere", RuntimeKeyPath: "/tmp/no-key"}
	h := s.Handler(key)
	for _, path := range []string{"/v1/status", "/v1/checks", "/v1/runtime/stop"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 401 {
			t.Fatalf("unauthenticated %s returned %d", path, w.Code)
		}
	}
}
func TestSignedMutationsFailClosedEvenWithWriteMode(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		dir := t.TempDir()
		socket := filepath.Join(dir, "agent.sock")
		keyPath := filepath.Join(dir, "agent.key")
		key, err := ipc.EnsureKey(keyPath, -1)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: (Server{WriteEnabled: enabled, RuntimeSocket: "/tmp/nowhere", RuntimeKeyPath: "/tmp/no-key"}).Handler(key)}
		l, err := ipc.Listen(socket)
		if err != nil {
			t.Fatal(err)
		}
		go srv.Serve(l)
		client := ipc.SignedClient(socket, keyPath)
		for _, path := range []string{"/v1/apply", "/v1/pki/revoke", "/v1/runtime/stop"} {
			req, _ := http.NewRequest(http.MethodPost, "http://agent"+path, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			expected := http.StatusLocked
			if enabled {
				expected = http.StatusNotImplemented
			}
			if resp.StatusCode != expected {
				t.Fatalf("enabled %v path %s got %d", enabled, path, resp.StatusCode)
			}
		}
		_ = srv.Close()
		_ = l.Close()
	}
}
func TestRuntimeUnavailableFailsClosed(t *testing.T) {
	s := Server{WriteEnabled: true, RuntimeSocket: "/tmp/nowhere", RuntimeKeyPath: "/tmp/missing"}
	if _, err := s.readRuntime(); err == nil {
		t.Fatal("runtime absent must return error")
	}
}

func TestAuthenticatedRuntimeProxy(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	secret, err := ipc.EnsureKey(keyPath, -1)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "runtime.sock")
	listener, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := &http.Server{Handler: ipc.Authenticated(secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"UNINITIALIZED","running":false,"tunAvailable":true,"diagnostics":[]}`))
	}))}
	go srv.Serve(listener)
	defer func() { _ = srv.Close(); _ = listener.Close() }()
	s := Server{WriteEnabled: false, RuntimeSocket: socket, RuntimeKeyPath: keyPath}
	status, err := s.readRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || status.State != "UNINITIALIZED" || !status.TUNAvailable {
		t.Fatalf("invalid authenticated IPC result %+v calls=%d", status, calls)
	}
	s.RuntimeKeyPath = filepath.Join(dir, "bad.key")
	if _, err := s.readRuntime(); err == nil {
		t.Fatal("missing IPC key must fail closed")
	}
}
