package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSQLite(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.Exec("CREATE TABLE data (id TEXT PRIMARY KEY, value TEXT)"); err != nil {
		t.Fatal(err)
	}
	const input = "hello'); DROP TABLE data; --"
	if err = d.Exec("INSERT INTO data(id,value) VALUES(?,?)", "id", input); err != nil {
		t.Fatal(err)
	}
	rows, err := d.Query("SELECT value FROM data WHERE id=?", "id")
	if err != nil || len(rows) != 1 || rows[0]["value"] != input {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if err = d.Transaction(func(tx *Tx) error {
		if e := tx.Exec("UPDATE data SET value=?", "bad"); e != nil {
			return e
		}
		return errors.New("rollback")
	}); err == nil {
		t.Fatal("didn't rollback")
	}
	rows, _ = d.Query("SELECT value FROM data WHERE id=?", "id")
	if rows[0]["value"] != input {
		t.Fatal("rollback failed")
	}
}
