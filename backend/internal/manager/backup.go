package manager

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Divad1111/openvpn-web/internal/backup"
)

var validBackupID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// BackupManifest stores only digests and sizes, never private keys or identity data.
type BackupManifest struct {
	Format        string `json:"format"`
	ID            string `json:"id"`
	CreatedAt     string `json:"createdAt"`
	AgentSHA256   string `json:"agentSHA256"`
	ManagerSHA256 string `json:"managerSHA256"`
}

// SnapshotFiles provides a consistent database snapshot and wraps the local
// encryption master key. Its output must never be sent to the Agent or Web.
func (a *Auth) SnapshotFiles() (map[string][]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	temp, err := os.CreateTemp(filepath.Dir(a.keyPath), "manager-db-snapshot-*.db")
	if err != nil {
		return nil, err
	}
	name := temp.Name()
	temp.Close()
	os.Remove(name)
	defer os.Remove(name)
	if err = a.db.Snapshot(name); err != nil {
		return nil, err
	}
	db, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	master, err := os.ReadFile(a.keyPath)
	if err != nil {
		return nil, err
	}
	if len(master) != 32 {
		return nil, errors.New("manager master key invalid")
	}
	return map[string][]byte{"manager/state.db": db, "manager/master.key": master}, nil
}

func (a *App) backupDirs() (string, string) {
	mainDir := a.BackupDir
	if mainDir == "" {
		mainDir = "/data/manager/backups"
	}
	exported := a.AgentEncryptedBackupDir
	if exported == "" {
		exported = "/data/export"
	}
	return mainDir, exported
}

// CreateBackup produces one portable tar bundle with two *independently*
// passphrase-encrypted payloads. Manager can read Agent ciphertext only.
func (a *App) CreateBackup(password string) (BackupManifest, error) {
	if len(password) < 16 || len(password) > 512 {
		return BackupManifest{}, errors.New("invalid backup password length")
	}
	id, err := randomHex(16)
	if err != nil {
		return BackupManifest{}, err
	}
	raw, code, err := a.callAgent("POST", "/v1/backups", map[string]string{"id": id, "passphrase": password})
	if err != nil {
		return BackupManifest{}, err
	}
	if code != 201 {
		return BackupManifest{}, fmt.Errorf("agent backup failed (status %d)", code)
	}
	var agentMeta struct {
		ID, SHA256 string
		Size       int
	}
	if err = json.Unmarshal(raw, &agentMeta); err != nil {
		return BackupManifest{}, err
	}
	if agentMeta.ID != id || agentMeta.Size < 100 || agentMeta.Size > backup.MaxPayload+100 {
		return BackupManifest{}, errors.New("invalid agent backup result")
	}
	managerFiles, err := a.Auth.SnapshotFiles()
	if err != nil {
		return BackupManifest{}, err
	}
	managerCipher, err := backup.Seal(managerFiles, password)
	if err != nil {
		return BackupManifest{}, err
	}
	mainDir, exportDir := a.backupDirs()
	agentFile := filepath.Join(exportDir, "agent-"+id+".seal")
	st, err := os.Lstat(agentFile)
	if err != nil {
		return BackupManifest{}, err
	}
	if !st.Mode().IsRegular() || st.Size() != int64(agentMeta.Size) {
		return BackupManifest{}, errors.New("unsafe agent backup output")
	}
	agentCipher, err := os.ReadFile(agentFile)
	if err != nil {
		return BackupManifest{}, err
	}
	if err = backup.VerifyHeader(agentCipher); err != nil {
		return BackupManifest{}, err
	}
	agentHash := sha256.Sum256(agentCipher)
	if hex.EncodeToString(agentHash[:]) != agentMeta.SHA256 {
		return BackupManifest{}, errors.New("agent backup digest mismatch")
	}
	managerHash := sha256.Sum256(managerCipher)
	manifest := BackupManifest{Format: "openvpn-ce-manager-v1", ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339), AgentSHA256: agentMeta.SHA256, ManagerSHA256: hex.EncodeToString(managerHash[:])}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return BackupManifest{}, err
	}
	if err = os.MkdirAll(mainDir, 0700); err != nil {
		return BackupManifest{}, err
	}
	tmp, err := os.CreateTemp(mainDir, "backup-*.tmp")
	if err != nil {
		return BackupManifest{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return BackupManifest{}, err
	}
	tw := tar.NewWriter(tmp)
	for _, member := range []struct {
		Name string
		Data []byte
	}{{"manifest.json", manifestBytes}, {"manager.seal", managerCipher}, {"agent.seal", agentCipher}} {
		if err = tw.WriteHeader(&tar.Header{Name: member.Name, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(member.Data))}); err != nil {
			tw.Close()
			tmp.Close()
			return BackupManifest{}, err
		}
		if _, err = tw.Write(member.Data); err != nil {
			tw.Close()
			tmp.Close()
			return BackupManifest{}, err
		}
	}
	if err = tw.Close(); err != nil {
		tmp.Close()
		return BackupManifest{}, err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return BackupManifest{}, err
	}
	if err = tmp.Close(); err != nil {
		return BackupManifest{}, err
	}
	if err = os.Rename(tmpName, filepath.Join(mainDir, id+".ovpnbackup")); err != nil {
		return BackupManifest{}, err
	}
	return manifest, nil
}

func (a *App) BackupListing() ([]map[string]any, error) {
	dir, _ := a.backupDirs()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, entry := range entries {
		name := entry.Name()
		id := strings.TrimSuffix(name, ".ovpnbackup")
		if !validBackupID.MatchString(id) || name != id+".ovpnbackup" || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		rows = append(rows, map[string]any{"id": id, "size": info.Size(), "createdAt": info.ModTime().UTC().Format(time.RFC3339), "encrypted": true})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["id"].(string) > rows[j]["id"].(string) })
	return rows, nil
}

// WriteBackup downloads an existing encrypted archive only after caller has
// passed the Docker write gate, an admin session and fresh TOTP challenge.
func (a *App) WriteBackup(w io.Writer, id string) error {
	if !validBackupID.MatchString(id) {
		return errors.New("invalid backup ID")
	}
	dir, _ := a.backupDirs()
	p := filepath.Join(dir, id+".ovpnbackup")
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > 2*(backup.MaxPayload+100)+16384 {
		return errors.New("unsafe backup file")
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, io.LimitReader(f, 2*(backup.MaxPayload+100)+16384))
	return err
}

// ValidatePortableBackup authenticates each component in memory without
// modifying any live database or key. Manager never decrypts Agent's sealed
// payload; its verification is delegated to Agent in a later restore workflow.
func (a *App) ValidatePortableBackup(id, password string) (BackupManifest, error) {
	if !validBackupID.MatchString(id) {
		return BackupManifest{}, errors.New("invalid backup ID")
	}
	dir, _ := a.backupDirs()
	data, err := os.ReadFile(filepath.Join(dir, id+".ovpnbackup"))
	if err != nil {
		return BackupManifest{}, err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	entries := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return BackupManifest{}, err
		}
		if h.Typeflag != tar.TypeReg || (h.Name != "manifest.json" && h.Name != "manager.seal" && h.Name != "agent.seal") || h.Size < 0 || h.Size > backup.MaxPayload+100 {
			return BackupManifest{}, errors.New("invalid portable archive entry")
		}
		if _, dup := entries[h.Name]; dup {
			return BackupManifest{}, errors.New("duplicate entry")
		}
		b := make([]byte, int(h.Size))
		if _, err = io.ReadFull(tr, b); err != nil {
			return BackupManifest{}, err
		}
		entries[h.Name] = b
	}
	var m BackupManifest
	if err = json.Unmarshal(entries["manifest.json"], &m); err != nil {
		return BackupManifest{}, err
	}
	if m.Format != "openvpn-ce-manager-v1" || m.ID != id {
		return BackupManifest{}, errors.New("unrecognized archive manifest")
	}
	aHash := sha256.Sum256(entries["agent.seal"])
	mHash := sha256.Sum256(entries["manager.seal"])
	if m.AgentSHA256 != hex.EncodeToString(aHash[:]) || m.ManagerSHA256 != hex.EncodeToString(mHash[:]) {
		return BackupManifest{}, errors.New("archive digest mismatch")
	}
	managerFiles, err := backup.Open(entries["manager.seal"], password)
	if err != nil {
		return BackupManifest{}, err
	}
	if len(managerFiles["manager/state.db"]) == 0 || len(managerFiles["manager/master.key"]) != 32 {
		return BackupManifest{}, errors.New("missing manager state files")
	}
	if err = backup.VerifyHeader(entries["agent.seal"]); err != nil {
		return BackupManifest{}, err
	}
	return m, nil
}

func (a *App) backupAccess(w http.ResponseWriter, r *http.Request, sess Session, input *struct{ Passphrase, TOTP string }) bool {
	if err := a.writable(); err != nil {
		rejectCode(w, err.Error())
		return false
	}
	if err := readJSON(r, input); err != nil {
		rejectCode(w, "INVALID_REQUEST")
		return false
	}
	if input.TOTP == "" || !a.verifyAdminTOTP(sess.Username, input.TOTP) {
		rejectCode(w, "TOTP_REQUIRED")
		return false
	}
	return true
}

func (a *App) handleCreateBackup(w http.ResponseWriter, r *http.Request, sess Session) {
	var input struct{ Passphrase, TOTP string }
	if !a.backupAccess(w, r, sess, &input) {
		return
	}
	m, err := a.CreateBackup(input.Passphrase)
	if err != nil {
		a.Auth.Audit(sess.Username, "backup-create", ipOf(r), "failed", "")
		rejectCode(w, "AGENT_UNAVAILABLE")
		return
	}
	a.Auth.Audit(sess.Username, "backup-create", ipOf(r), "success", m.ID)
	respond(w, http.StatusCreated, m)
}
func (a *App) handleDownloadBackup(w http.ResponseWriter, r *http.Request, sess Session, id string) {
	var input struct{ Passphrase, TOTP string }
	if !a.backupAccess(w, r, sess, &input) {
		return
	}
	// Require the backup passphrase for export: the downloaded bundle contains
	// encrypted private material and must be opened only by the holder.
	if _, err := a.ValidatePortableBackup(id, input.Passphrase); err != nil {
		rejectCode(w, "FORBIDDEN")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="openvpn-ce-%s.ovpnbackup"`, id))
	w.Header().Set("Cache-Control", "no-store")
	if err := a.WriteBackup(w, id); err != nil {
		a.Auth.Audit(sess.Username, "backup-download", ipOf(r), "failed", "")
		return
	}
	a.Auth.Audit(sess.Username, "backup-download", ipOf(r), "success", id)
}
func (a *App) handleValidateBackup(w http.ResponseWriter, r *http.Request, sess Session, id string) {
	var input struct{ Passphrase, TOTP string }
	if !a.backupAccess(w, r, sess, &input) {
		return
	}
	m, err := a.ValidatePortableBackup(id, input.Passphrase)
	if err != nil {
		rejectCode(w, "FORBIDDEN")
		return
	}
	// Only Agent can decrypt the PKI: Manager validates its own component and
	// asks Agent to verify the private-key component over authenticated IPC.
	raw, status, err := a.callAgent("POST", "/v1/backups/"+id+"/validate", map[string]string{"passphrase": input.Passphrase})
	if err != nil || status != 200 {
		rejectCode(w, "AGENT_UNAVAILABLE")
		return
	}
	var agentResult map[string]any
	if err = json.Unmarshal(raw, &agentResult); err != nil {
		rejectCode(w, "AGENT_UNAVAILABLE")
		return
	}
	a.Auth.Audit(sess.Username, "backup-validate", ipOf(r), "success", id)
	respond(w, 200, map[string]any{"manifest": m, "agent": agentResult, "restoreSupported": false})
}
