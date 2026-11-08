// Package store wraps system SQLite through cgo, avoiding a network-fetched
// Go SQLite driver. All SQL identifiers are application constants; user values
// are *always* bound as query parameters, never interpolated into SQL text.
package store

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>
static int bind_transient(sqlite3_stmt *s, int pos, const char *val) {
  return sqlite3_bind_text(s, pos, val, -1, SQLITE_TRANSIENT);
}
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"
)

type DB struct {
	mu sync.Mutex
	db *C.sqlite3
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// SQLite defaults may create world-readable DB files under umask 022.
	// Create the database first with explicit 0600, and reject symlinks.
	if st, e := os.Lstat(path); e == nil {
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("unsafe SQLite database type or permissions")
		}
	} else if os.IsNotExist(e) {
		f, ce := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if ce != nil {
			return nil, ce
		}
		if ce = f.Close(); ce != nil {
			return nil, ce
		}
	} else {
		return nil, e
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var ptr *C.sqlite3
	rc := C.sqlite3_open_v2(cpath, &ptr, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil)
	if rc != C.SQLITE_OK {
		msg := "cannot open database"
		if ptr != nil {
			msg = C.GoString(C.sqlite3_errmsg(ptr))
			C.sqlite3_close(ptr)
		}
		return nil, fmt.Errorf("sqlite open: %s", msg)
	}
	db := &DB{db: ptr}
	C.sqlite3_busy_timeout(ptr, 5000)
	if _, err := db.Query("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	for _, q := range []string{"PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if err := db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return db, nil
}
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return nil
	}
	if C.sqlite3_close(d.db) != C.SQLITE_OK {
		return errors.New("sqlite close busy")
	}
	d.db = nil
	return nil
}
func (d *DB) prepare(sql string, args []string) (*C.sqlite3_stmt, error) {
	if d.db == nil {
		return nil, errors.New("closed database")
	}
	cs := C.CString(sql)
	defer C.free(unsafe.Pointer(cs))
	var stmt *C.sqlite3_stmt
	if C.sqlite3_prepare_v2(d.db, cs, -1, &stmt, nil) != C.SQLITE_OK {
		return nil, fmt.Errorf("sqlite prepare: %s", C.GoString(C.sqlite3_errmsg(d.db)))
	}
	if int(C.sqlite3_bind_parameter_count(stmt)) != len(args) {
		C.sqlite3_finalize(stmt)
		return nil, errors.New("sqlite parameter count mismatch")
	}
	for idx, arg := range args {
		v := C.CString(arg)
		rc := C.bind_transient(stmt, C.int(idx+1), v)
		C.free(unsafe.Pointer(v))
		if rc != C.SQLITE_OK {
			C.sqlite3_finalize(stmt)
			return nil, errors.New("sqlite bind error")
		}
	}
	return stmt, nil
}
func (d *DB) Exec(sql string, args ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.exec(sql, args)
}
func (d *DB) exec(sql string, args []string) error {
	s, err := d.prepare(sql, args)
	if err != nil {
		return err
	}
	defer C.sqlite3_finalize(s)
	rc := C.sqlite3_step(s)
	if rc != C.SQLITE_DONE {
		return fmt.Errorf("sqlite step: %s", C.GoString(C.sqlite3_errmsg(d.db)))
	}
	return nil
}
func (d *DB) Query(sql string, args ...string) ([]map[string]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.prepare(sql, args)
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(s)
	rows := make([]map[string]string, 0)
	for {
		rc := C.sqlite3_step(s)
		if rc == C.SQLITE_DONE {
			return rows, nil
		}
		if rc != C.SQLITE_ROW {
			return nil, fmt.Errorf("sqlite query: %s", C.GoString(C.sqlite3_errmsg(d.db)))
		}
		row := make(map[string]string)
		for j := C.int(0); j < C.sqlite3_column_count(s); j++ {
			key := C.GoString(C.sqlite3_column_name(s, j))
			p := C.sqlite3_column_text(s, j)
			if p != nil {
				row[key] = C.GoString((*C.char)(unsafe.Pointer(p)))
			} else {
				row[key] = ""
			}
		}
		rows = append(rows, row)
	}
}

// Transaction serializes all queries in one database connection, including rollback on panic.
func (d *DB) Transaction(fn func(tx *Tx) error) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err = d.exec("BEGIN IMMEDIATE", nil); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = d.exec("ROLLBACK", nil)
		}
	}()
	if err = fn(&Tx{db: d}); err != nil {
		return err
	}
	if err = d.exec("COMMIT", nil); err != nil {
		return err
	}
	committed = true
	return nil
}

type Tx struct{ db *DB }

func (t *Tx) Exec(sql string, args ...string) error { return t.db.exec(sql, args) }
func (t *Tx) Query(sql string, args ...string) ([]map[string]string, error) {
	s, err := t.db.prepare(sql, args)
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(s)
	var rows []map[string]string
	for {
		rc := C.sqlite3_step(s)
		if rc == C.SQLITE_DONE {
			return rows, nil
		}
		if rc != C.SQLITE_ROW {
			return nil, errors.New("sqlite transaction query failed")
		}
		row := map[string]string{}
		for j := C.int(0); j < C.sqlite3_column_count(s); j++ {
			key := C.GoString(C.sqlite3_column_name(s, j))
			p := C.sqlite3_column_text(s, j)
			if p != nil {
				row[key] = C.GoString((*C.char)(unsafe.Pointer(p)))
			} else {
				row[key] = ""
			}
		}
		rows = append(rows, row)
	}
}
