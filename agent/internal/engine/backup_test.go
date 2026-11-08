package engine

import (
	"github.com/Divad1111/openvpn-web/internal/backup"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentEncryptedSnapshotRejectsTamperAndIncludesPKI(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "agent")
	runDir := filepath.Join(root, "runtime")
	exportDir := filepath.Join(root, "export")
	e, err := New(agentDir, runDir, filepath.Join(root, "missing.sock"), filepath.Join(root, "missing.key"), "/not-needed", 1194)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for name, content := range map[string]string{
		"pki/ca.crt":            "example-ca",
		"pki/private/ca.key":    "encrypted-test-ca-key",
		"pki/issued/server.crt": "server-cert",
		"runtime/server.conf":   "port 1194",
	} {
		target := filepath.Join(agentDir, name)
		if strings.HasPrefix(name, "runtime/") {
			target = filepath.Join(runDir, strings.TrimPrefix(name, "runtime/"))
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(target, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	id := "0123456789abcdef0123456789abcdef"
	meta, err := e.CreateEncryptedBackup(id, "a-long-independent-backup-password", exportDir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != id {
		t.Fatal("bad id")
	}
	ciphertext, err := os.ReadFile(filepath.Join(exportDir, "agent-"+id+".seal"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), "encrypted-test-ca-key") {
		t.Fatal("CA secret leaked")
	}
	decoded, err := backup.Open(ciphertext, "a-long-independent-backup-password")
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded["pki/private/ca.key"]) != "encrypted-test-ca-key" {
		t.Fatal("PKI not included")
	}
	if len(decoded["agent/metadata.db"]) == 0 {
		t.Fatal("database missing")
	}
	result, err := e.ValidateEncryptedBackup(id, "a-long-independent-backup-password", exportDir)
	if err != nil || result["validated"] != true {
		t.Fatalf("validation failed %v %v", result, err)
	}
	if _, err = e.ValidateEncryptedBackup(id, "incorrect-backup-password", exportDir); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err = e.CreateEncryptedBackup(id, "a-long-independent-backup-password", exportDir); err == nil {
		t.Fatal("duplicate backup accepted")
	}
}
