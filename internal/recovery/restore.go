package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Divad1111/openvpn-web/internal/lifecycle"
)

// Roots are fully explicit Compose volume mountpoints. The restoration tool
// never accepts an arbitrary archive destination path from the Web UI.
type Roots struct{ Manager, Agent, Runtime, RuntimeIPC string }

type operation struct {
	Root, Name string
	RemoveOnly bool
	OldExists  bool
}
type journal struct {
	ID         string
	CreatedAt  string
	Operations []operation
}

func (r Roots) path(which string) (string, error) {
	switch which {
	case "manager":
		return r.Manager, nil
	case "agent":
		return r.Agent, nil
	case "runtime":
		return r.Runtime, nil
	}
	return "", errors.New("invalid recovery root")
}

func (r Roots) lockPaths() []string {
	return []string{
		filepath.Join(r.Manager, ".manager-live.lock"),
		filepath.Join(r.Agent, ".agent-live.lock"),
		filepath.Join(r.RuntimeIPC, ".runtime-live.lock"),
	}
}

// Plan validates that all volumes are offline before writing staged files.
// A restore is inherently cross-volume; an on-volume journal and retained
// rollback copies permit explicit recovery after power loss or failed startup.
func Apply(arc Archive, roots Roots) error {
	if !backupIDRegexp.MatchString(arc.Manifest.ID) {
		return errors.New("invalid ID")
	}
	locks, err := lifecycle.CheckStopped(roots.lockPaths()...)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range locks {
			f.Close()
		}
	}()
	id := arc.Manifest.ID
	journalPath := filepath.Join(roots.Manager, ".ovpn-restore-journal-"+id+".json")
	if _, err = os.Lstat(journalPath); err == nil {
		return errors.New("existing restore journal; rollback or resolve it before new restore")
	}
	stages := map[string]string{}
	rollbacks := map[string]string{}
	for _, rootName := range []string{"manager", "agent", "runtime"} {
		root, err := roots.path(rootName)
		if err != nil {
			return err
		}
		if st, err := os.Lstat(root); err != nil || !st.IsDir() {
			return fmt.Errorf("recovery volume missing or invalid: %s", rootName)
		}
		stage := filepath.Join(root, ".ovpn-restore-stage-"+id)
		rb := filepath.Join(root, ".ovpn-restore-old-"+id)
		for _, p := range []string{stage, rb} {
			if _, err := os.Lstat(p); err == nil {
				return errors.New("existing restore staging/rollback directory")
			}
		}
		if err := os.Mkdir(stage, 0700); err != nil {
			return err
		}
		if err := os.Mkdir(rb, 0700); err != nil {
			return err
		}
		stages[rootName] = stage
		rollbacks[rootName] = rb
	}
	ops := make([]operation, 0, 32)
	add := func(root, name string, data []byte) error {
		stage := filepath.Join(stages[root], name)
		if err := os.MkdirAll(filepath.Dir(stage), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(stage, data, 0600); err != nil {
			return err
		}
		ops = append(ops, operation{Root: root, Name: name})
		return nil
	}
	// WAL/SHM files are moved out before databases are replaced: old WAL must
	// never be paired with restored SQLite main database files.
	for _, root := range []string{"manager", "agent"} {
		name := "state.db"
		if root == "agent" {
			name = "metadata.db"
		}
		ops = append(ops, operation{Root: root, Name: name + "-wal", RemoveOnly: true}, operation{Root: root, Name: name + "-shm", RemoveOnly: true})
	}
	if err := add("manager", "state.db", arc.Manager["manager/state.db"]); err != nil {
		return err
	}
	if err := add("manager", "master.key", arc.Manager["manager/master.key"]); err != nil {
		return err
	}
	if err := add("agent", "metadata.db", arc.Agent["agent/metadata.db"]); err != nil {
		return err
	}
	if err := add("agent", "config.json", arc.Agent["agent/config.json"]); err != nil {
		return err
	}
	pkiNames := make([]string, 0)
	for name := range arc.Agent {
		if strings.HasPrefix(name, "pki/") {
			pkiNames = append(pkiNames, name)
		}
	}
	sort.Strings(pkiNames)
	for _, name := range pkiNames {
		rel := strings.TrimPrefix(name, "pki/")
		target := filepath.Join(stages["agent"], "pki", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(target, arc.Agent[name], 0600); err != nil {
			return err
		}
	}
	ops = append(ops, operation{Root: "agent", Name: "pki"})
	runtimeNames := []string{"ca.crt", "crl.pem", "network.json", "server.conf", "server.crt", "server.key", "tls-crypt.key"}
	for _, name := range runtimeNames {
		if err := add("runtime", name, arc.Agent["runtime/"+name]); err != nil {
			return err
		}
	}
	for i := range ops {
		root, _ := roots.path(ops[i].Root)
		p := filepath.Join(root, ops[i].Name)
		st, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if st.Mode()&os.ModeSymlink != 0 || (!st.IsDir() && !st.Mode().IsRegular()) {
				return errors.New("unsafe restore destination")
			}
			if ops[i].Name == "pki" && !st.IsDir() {
				return errors.New("PKI directory has invalid type")
			}
			ops[i].OldExists = true
		}
	}
	j := journal{ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339), Operations: ops}
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	if err := writeJournal(journalPath, b); err != nil {
		return err
	}
	for _, op := range ops {
		root, _ := roots.path(op.Root)
		dest := filepath.Join(root, op.Name)
		old := filepath.Join(rollbacks[op.Root], op.Name)
		if op.OldExists {
			if err = os.MkdirAll(filepath.Dir(old), 0700); err != nil {
				break
			}
			if err = os.Rename(dest, old); err != nil {
				break
			}
		}
		if !op.RemoveOnly {
			staged := filepath.Join(stages[op.Root], op.Name)
			if err = os.Rename(staged, dest); err != nil {
				break
			}
		}
	}
	if err != nil {
		_ = rollbackUnsafe(id, roots)
		return fmt.Errorf("restore interrupted and rollback attempted: %w", err)
	}
	// Keep the journal and old data until the operator confirms normal startup.
	// This enables rollback even after process exit; rollback copies remain mode
	// 0700 within the original protected Docker volumes.
	return nil
}

func writeJournal(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Rollback restores the old files/directories from recorded paths. A missing
// rollback copy with OldExists=true is treated as a crash before that move,
// and any unrecognized target type fails rather than deleting host data.
func Rollback(id string, roots Roots) error {
	locks, err := lifecycle.CheckStopped(roots.lockPaths()...)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range locks {
			f.Close()
		}
	}()
	return rollbackUnsafe(id, roots)
}

func rollbackUnsafe(id string, roots Roots) error {
	if !backupIDRegexp.MatchString(id) {
		return errors.New("invalid restore ID")
	}
	journalPath := filepath.Join(roots.Manager, ".ovpn-restore-journal-"+id+".json")
	b, err := os.ReadFile(journalPath)
	if err != nil {
		return err
	}
	var j journal
	if err = json.Unmarshal(b, &j); err != nil {
		return err
	}
	if j.ID != id {
		return errors.New("restore journal identifier mismatch")
	}
	var failures []error
	for i := len(j.Operations) - 1; i >= 0; i-- {
		op := j.Operations[i]
		root, e := roots.path(op.Root)
		if e != nil {
			failures = append(failures, e)
			continue
		}
		dest := filepath.Join(root, op.Name)
		old := filepath.Join(root, ".ovpn-restore-old-"+id, op.Name)
		staged := filepath.Join(root, ".ovpn-restore-stage-"+id, op.Name)
		_, e = os.Lstat(old)
		oldBackupExists := e == nil
		if e != nil && !os.IsNotExist(e) {
			failures = append(failures, e)
			continue
		}
		if !oldBackupExists {
			if op.OldExists {
				continue
			} // not applied yet
			if _, e = os.Lstat(staged); e == nil {
				continue
			} // staged new file still present
		}
		if st, e := os.Lstat(dest); e == nil {
			if st.Mode()&os.ModeSymlink != 0 {
				failures = append(failures, errors.New("unsafe restore rollback destination"))
				continue
			}
			if e = os.MkdirAll(filepath.Dir(staged), 0700); e != nil {
				failures = append(failures, e)
				continue
			}
			if e = os.Rename(dest, staged); e != nil {
				failures = append(failures, e)
				continue
			}
		} else if !os.IsNotExist(e) {
			failures = append(failures, e)
			continue
		}
		if oldBackupExists {
			if e = os.Rename(old, dest); e != nil {
				failures = append(failures, e)
			}
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return os.Remove(journalPath)
}
