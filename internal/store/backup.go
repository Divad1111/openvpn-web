package store

/*
#include <sqlite3.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

// Snapshot writes a consistent SQLite backup including data resident in WAL.
// Callers must not back up the live .db file alone.
func (d *DB) Snapshot(dest string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.db == nil {
		return errors.New("database closed")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), "snapshot-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	cpath := C.CString(name)
	defer C.free(unsafe.Pointer(cpath))
	var dst *C.sqlite3
	rc := C.sqlite3_open_v2(cpath, &dst, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil)
	if rc != C.SQLITE_OK {
		if dst != nil {
			C.sqlite3_close(dst)
		}
		return errors.New("backup database open failed")
	}
	defer C.sqlite3_close(dst)
	mainName := C.CString("main")
	defer C.free(unsafe.Pointer(mainName))
	b := C.sqlite3_backup_init(dst, mainName, d.db, mainName)
	if b == nil {
		return fmt.Errorf("sqlite backup initialization failed: %s", C.GoString(C.sqlite3_errmsg(dst)))
	}
	rc = C.sqlite3_backup_step(b, -1)
	finish := C.sqlite3_backup_finish(b)
	if rc != C.SQLITE_DONE || finish != C.SQLITE_OK {
		return errors.New("sqlite backup step failed")
	}
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, dest)
}
