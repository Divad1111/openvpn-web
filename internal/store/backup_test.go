package store

import (
	"path/filepath"
	"testing"
)

func TestSnapshotCoversWAL(t *testing.T) {
	root := t.TempDir()
	db, err := Open(filepath.Join(root, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Exec("CREATE TABLE secrets (id TEXT PRIMARY KEY,value TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if err = db.Exec("INSERT INTO secrets VALUES(?,?)", "a", "value-from-wal"); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, "snapshot.db")
	if err = db.Snapshot(backup); err != nil {
		t.Fatal(err)
	}
	other, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	rows, err := other.Query("SELECT value FROM secrets WHERE id=?", "a")
	if err != nil || len(rows) != 1 || rows[0]["value"] != "value-from-wal" {
		t.Fatalf("snapshot mismatch: %v %v", rows, err)
	}
}
