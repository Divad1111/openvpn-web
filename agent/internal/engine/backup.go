package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Divad1111/openvpn-web/internal/backup"
)

var backupID = regexp.MustCompile(`^[a-f0-9]{32}$`)

// BackupMeta contains no CA/private key material.
type BackupMeta struct {
	ID        string `json:"id"`
	CreatedAt string `json:"createdAt"`
	Size      int    `json:"size"`
	SHA256    string `json:"sha256"`
}

// CreateEncryptedBackup writes an encrypted snapshot of the Agent's metadata,
// PKI, and Runtime configuration into a separate export volume. The manager
// can read this ciphertext but cannot read the Agent's private key volume.
func (e *Engine) CreateEncryptedBackup(id, passphrase, exportDir string) (BackupMeta, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !backupID.MatchString(id) {
		return BackupMeta{}, errors.New("invalid backup identifier")
	}
	if !e.PKI.exists() {
		return BackupMeta{}, errors.New("PKI not initialized")
	}
	if err := os.MkdirAll(exportDir, 0700); err != nil {
		return BackupMeta{}, err
	}
	target := filepath.Join(exportDir, "agent-"+id+".seal")
	if _, err := os.Lstat(target); err == nil {
		return BackupMeta{}, errors.New("backup already exists")
	} else if !os.IsNotExist(err) {
		return BackupMeta{}, err
	}
	scratch, err := os.CreateTemp(e.AgentDir, "backup-snapshot-*.db")
	if err != nil {
		return BackupMeta{}, err
	}
	filename := scratch.Name()
	scratch.Close()
	os.Remove(filename)
	defer os.Remove(filename)
	if err = e.DB.Snapshot(filename); err != nil {
		return BackupMeta{}, err
	}
	dbBytes, err := os.ReadFile(filename)
	if err != nil {
		return BackupMeta{}, err
	}
	files := map[string][]byte{"agent/metadata.db": dbBytes}
	// The PKI is read while the Engine's mutation lock is held. No symlinks,
	// devices, directories or caller-chosen paths are archived.
	err = filepath.WalkDir(e.PKI.Dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("unsafe PKI filesystem entry")
		}
		rel, err := filepath.Rel(e.PKI.Dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files["pki/"+filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return BackupMeta{}, err
	}
	if b, err := os.ReadFile(filepath.Join(e.AgentDir, "config.json")); err == nil {
		files["agent/config.json"] = b
	} else if !os.IsNotExist(err) {
		return BackupMeta{}, err
	}
	for _, name := range []string{"server.conf", "server.crt", "server.key", "ca.crt", "crl.pem", "tls-crypt.key", "network.json"} {
		p := filepath.Join(e.RuntimeDir, name)
		stat, err := os.Lstat(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return BackupMeta{}, err
		}
		if !stat.Mode().IsRegular() {
			return BackupMeta{}, errors.New("unsafe runtime config filesystem entry")
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return BackupMeta{}, err
		}
		files["runtime/"+name] = b
	}
	sealed, err := backup.Seal(files, passphrase)
	if err != nil {
		return BackupMeta{}, err
	}
	if err = AtomicFile(target, sealed, 0600); err != nil {
		return BackupMeta{}, err
	}
	h := sha256.Sum256(sealed)
	info := BackupMeta{ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339), Size: len(sealed), SHA256: hex.EncodeToString(h[:])}
	e.Audit("backup-create", id, "success")
	return info, nil
}

// ValidateEncryptedBackup authenticates backup contents without altering state.
// A restore must not be attempted until separate offline preflight can verify
// an entire multi-container bundle with rollback and running-process shutdown.
func (e *Engine) ValidateEncryptedBackup(id, passphrase, exportDir string) (map[string]any, error) {
	if !backupID.MatchString(id) {
		return nil, errors.New("invalid backup identifier")
	}
	blob, err := os.ReadFile(filepath.Join(exportDir, "agent-"+id+".seal"))
	if err != nil {
		return nil, err
	}
	files, err := backup.Open(blob, passphrase)
	if err != nil {
		return nil, err
	}
	for _, required := range []string{"agent/metadata.db", "pki/ca.crt", "pki/private/ca.key", "pki/issued/server.crt"} {
		if len(files[required]) == 0 {
			return nil, fmt.Errorf("missing required backup member: %s", required)
		}
	}
	return map[string]any{"files": len(files), "encrypted": true, "validated": true, "restoreApplied": false}, nil
}
