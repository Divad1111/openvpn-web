package recovery

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Divad1111/openvpn-web/internal/backup"
	"github.com/Divad1111/openvpn-web/internal/lifecycle"
	"github.com/Divad1111/openvpn-web/internal/store"
)

func sqliteSnapshot(t *testing.T) []byte {
	t.Helper()
	folder := t.TempDir()
	db, err := store.Open(filepath.Join(folder, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`CREATE TABLE smoke (id INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec(`INSERT INTO smoke(id) VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(folder, "out.db")
	if err = db.Snapshot(dst); err != nil {
		t.Fatal(err)
	}
	db.Close()
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func fixture(t *testing.T) (path, id, pass string) {
	t.Helper()
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub.Public(), pub)
	if err != nil {
		t.Fatal(err)
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	manager := map[string][]byte{"manager/state.db": sqliteSnapshot(t), "manager/master.key": bytes.Repeat([]byte{7}, 32)}
	agent := map[string][]byte{"agent/metadata.db": sqliteSnapshot(t), "agent/config.json": []byte(`{"vpnCIDR":"10.8.0.0/24"}`), "pki/ca.crt": pemCA, "pki/private/ca.key": []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nTEST\n-----END ENCRYPTED PRIVATE KEY-----"), "pki/issued/server.crt": pemCA, "pki/private/server.key": []byte("server-private"), "runtime/server.conf": []byte("proto tcp-server\nport 1194\n"), "runtime/server.crt": pemCA, "runtime/server.key": []byte("server-private"), "runtime/ca.crt": pemCA, "runtime/crl.pem": []byte("crl"), "runtime/tls-crypt.key": []byte("tls"), "runtime/network.json": []byte(`{"lanCIDR":"192.168.1.0/24"}`)}
	pass = "a-secure-test-passphrase-1234"
	mc, err := backup.Seal(manager, pass)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := backup.Seal(agent, pass)
	if err != nil {
		t.Fatal(err)
	}
	mh := sha256.Sum256(mc)
	ah := sha256.Sum256(ac)
	id = "1234567890abcdef1234567890abcdef"
	manifest, _ := json.Marshal(Manifest{Format: "openvpn-ce-manager-v1", ID: id, AgentSHA256: hex.EncodeToString(ah[:]), ManagerSHA256: hex.EncodeToString(mh[:])})
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for name, data := range map[string][]byte{"manifest.json": manifest, "manager.seal": mc, "agent.seal": ac} {
		if err = tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), id+".ovpnbackup")
	if err = os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path, id, pass
}
func roots(t *testing.T) Roots {
	t.Helper()
	base := t.TempDir()
	r := Roots{Manager: filepath.Join(base, "manager"), Agent: filepath.Join(base, "agent"), Runtime: filepath.Join(base, "runtime"), RuntimeIPC: filepath.Join(base, "runtime-ipc")}
	for _, p := range []string{r.Manager, r.Agent, r.Runtime, r.RuntimeIPC} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return r
}
func TestPortableBackupApplyAndRollback(t *testing.T) {
	path, id, pass := fixture(t)
	archive, err := ReadPortable(path, id, pass)
	if err != nil {
		t.Fatal(err)
	}
	r := roots(t)
	if err = Apply(archive, r); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(r.Manager, "state.db"), filepath.Join(r.Agent, "pki/ca.crt"), filepath.Join(r.Runtime, "server.conf")} {
		if _, err = os.Stat(p); err != nil {
			t.Errorf("expected recovered %s: %v", p, err)
		}
	}
	if err = Rollback(id, r); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(r.Manager, "state.db")); !os.IsNotExist(err) {
		t.Errorf("expected offline rollback to remove restored db: %v", err)
	}
}
func TestPortableBackupInvalidPassphrase(t *testing.T) {
	p, id, _ := fixture(t)
	if _, err := ReadPortable(p, id, "wrong-passphrase"); err == nil {
		t.Fatal("invalid passphrase accepted")
	}
}
func TestRestoreFailsWhenManagerRunning(t *testing.T) {
	p, id, pass := fixture(t)
	data, err := ReadPortable(p, id, pass)
	if err != nil {
		t.Fatal(err)
	}
	r := roots(t)
	lock, err := lifecycle.Hold(filepath.Join(r.Manager, ".manager-live.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := Apply(data, r); err == nil {
		t.Fatal("restore accepted while manager lock held")
	}
}
func TestTamperedBackupRejected(t *testing.T) {
	p, id, pass := fixture(t)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x08
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPortable(p, id, pass); err == nil {
		t.Fatal("tampered archive accepted")
	}
}

func TestOfflineRollbackPreservesExistingData(t *testing.T) {
	p, id, pass := fixture(t)
	archive, err := ReadPortable(p, id, pass)
	if err != nil {
		t.Fatal(err)
	}
	r := roots(t)
	original := []byte("original manager database bytes")
	target := filepath.Join(r.Manager, "state.db")
	if err = os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = Apply(archive, r); err != nil {
		t.Fatal(err)
	}
	now, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(now, original) {
		t.Fatal("restore did not replace target")
	}
	if err = Rollback(id, r); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatal("rollback did not restore prior data")
	}
}
