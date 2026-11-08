package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Divad1111/openvpn-web/internal/backup"
	"github.com/Divad1111/openvpn-web/internal/ipc"
)

func TestManagerEncryptedBackupCombinesOnlyAgentCiphertext(t *testing.T) {
	root := t.TempDir()
	exportDir := filepath.Join(root, "ciphertext-export")
	if err := os.MkdirAll(exportDir, 0700); err != nil {
		t.Fatal(err)
	}
	auth, err := OpenAuth(filepath.Join(root, "manager", "state.db"), filepath.Join(root, "manager", "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	sock := filepath.Join(root, "agent.sock")
	keypath := filepath.Join(root, "agent.key")
	key, err := ipc.EnsureKey(keypath, -1)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/backups", func(w http.ResponseWriter, r *http.Request) {
		var input struct{ ID, Passphrase string }
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			w.WriteHeader(400)
			return
		}
		ciphertext, err := backup.Seal(map[string][]byte{"pki/private/ca.key": []byte("secret-agent-private-key"), "pki/ca.crt": []byte("test-ca")}, input.Passphrase)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		if err = os.WriteFile(filepath.Join(exportDir, "agent-"+input.ID+".seal"), ciphertext, 0600); err != nil {
			w.WriteHeader(500)
			return
		}
		sum := sha256.Sum256(ciphertext)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"ID": input.ID, "SHA256": hex.EncodeToString(sum[:]), "Size": len(ciphertext)})
	})
	server := &http.Server{Handler: ipc.Authenticated(key, mux)}
	defer server.Close()
	go server.Serve(listener)
	// The signed Unix transport must be ready before requesting a backup.
	time.Sleep(10 * time.Millisecond)
	app := &App{Auth: auth, AgentSocket: sock, AgentKeyPath: keypath, BackupDir: filepath.Join(root, "manager", "backups"), AgentEncryptedBackupDir: exportDir, WriteEnabled: true}
	pass := "another-long-independent-password"
	m, err := app.CreateBackup(pass)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(filepath.Join(app.BackupDir, m.ID+".ovpnbackup"))
	if err != nil {
		t.Fatal(err)
	}
	if string(bundle) == "" {
		t.Fatal("empty archive")
	}
	if m.Format != "openvpn-ce-manager-v1" {
		t.Fatal("bad format")
	}
	if _, err := app.ValidatePortableBackup(m.ID, pass); err != nil {
		t.Fatal(err)
	}
	if _, err := app.ValidatePortableBackup(m.ID, "wrong-but-long-password"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}
