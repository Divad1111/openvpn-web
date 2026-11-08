package ipc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestKeyPersistenceAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ipc.key")
	first, err := EnsureKey(path, -1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EnsureKey(path, -1)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("secret must persist across restarts", err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0640 {
		t.Fatalf("permission %o", st.Mode().Perm())
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("unsafe permission must be rejected")
	}
	if _, err := EnsureKey(path, -1); err == nil {
		t.Fatal("must not repair corrupted key")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("symlink must be rejected")
	}
}

func TestAuthenticatedRejectsTamperReplayExpiredAndUnknown(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := Authenticated(key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	sign := func(method, path string, body []byte, ts string, nonce string) *http.Request {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("X-IPC-Timestamp", ts)
		req.Header.Set("X-IPC-Nonce", nonce)
		req.Header.Set("X-IPC-Signature", mac(key, method, req.URL.RequestURI(), ts, nonce, body))
		return req
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	n := hex.EncodeToString(bytes.Repeat([]byte{1}, 16))
	good := sign("POST", "http://local/v1/status?format=json", []byte("ok"), now, n)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, good)
	if w.Code != 204 {
		t.Fatalf("valid signed request status %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, sign("POST", "http://local/v1/status?format=json", []byte("ok"), now, n))
	if w.Code != 401 {
		t.Fatalf("replay status %d", w.Code)
	}
	w = httptest.NewRecorder()
	bad := sign("POST", "http://local/v1/status", []byte("ok"), now, hex.EncodeToString(bytes.Repeat([]byte{2}, 16)))
	bad.URL.RawQuery = "injected=true"
	h.ServeHTTP(w, bad)
	if w.Code != 401 {
		t.Fatalf("tampered url status %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, sign("POST", "http://local/v1/status", nil, "1000", hex.EncodeToString(bytes.Repeat([]byte{3}, 16))))
	if w.Code != 401 {
		t.Fatalf("expired status %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/status", nil))
	if w.Code != 401 {
		t.Fatalf("unsigned status %d", w.Code)
	}
	if calls != 1 {
		t.Fatalf("expected only one request forwarded, got %d", calls)
	}
}

func TestSignedClientOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "service.sock")
	secret := filepath.Join(dir, "secret.key")
	key, err := EnsureKey(secret, -1)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: Authenticated(key, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))}
	go server.Serve(l)
	defer func() { server.Close(); l.Close() }()
	resp, err := SignedClient(sock, secret).Get("http://service/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
