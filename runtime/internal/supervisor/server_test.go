package supervisor

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Divad1111/openvpn-web/internal/ipc"
)

func TestConfigInspectionDoesNotStartVPN(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "server.conf")
	bin := filepath.Join(dir, "openvpn")
	if err := os.WriteFile(bin, []byte("stub"), 0700); err != nil {
		t.Fatal(err)
	}
	i := Inspector{ConfigPath: config, TUNPath: "/dev/null", BinaryPath: bin}
	st := i.Inspect()
	if st.State != "UNINITIALIZED" || st.Running || !st.TUNAvailable || !st.BinaryAvailable {
		t.Fatalf("unexpected %+v", st)
	}
	if err := os.WriteFile(config, []byte("proto tcp-server\n"), 0640); err != nil {
		t.Fatal(err)
	}
	st = i.Inspect()
	if st.State != "CONFIG_PRESENT_UNVALIDATED" || st.Running || !st.ConfigSafe {
		t.Fatalf("unexpected %+v", st)
	}
	if err := os.Chmod(config, 0666); err != nil {
		t.Fatal(err)
	}
	st = i.Inspect()
	if st.State != "UNSAFE_CONFIG" || st.ConfigSafe {
		t.Fatalf("writable config must be rejected %+v", st)
	}
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, config); err != nil {
		t.Fatal(err)
	}
	if st = i.Inspect(); st.State != "UNSAFE_CONFIG" {
		t.Fatalf("symlink config must be rejected %+v", st)
	}
}
func TestAuthenticatedStatusNoWrites(t *testing.T) {
	dir := t.TempDir()
	secret, err := ipc.EnsureKey(filepath.Join(dir, "token"), -1)
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(Inspector{ConfigPath: filepath.Join(dir, "missing"), TUNPath: "/dev/null", BinaryPath: filepath.Join(dir, "missing-bin")}, secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if w.Code != 401 {
		t.Fatalf("unsigned request must fail: %d", w.Code)
	}
	sock := filepath.Join(dir, "runtime.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: h}
	go server.Serve(l)
	defer func() { server.Close(); l.Close() }()
	client := ipc.SignedClient(sock, filepath.Join(dir, "token"))
	resp, err := client.Get("http://runtime/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	b := new(bytes.Buffer)
	b.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(b.Bytes(), []byte("UNINITIALIZED")) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, b.String())
	}
	req, _ := http.NewRequest(http.MethodPost, "http://runtime/v1/start", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("runtime must not allow start: %d", resp.StatusCode)
	}
}
