package ipc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketRecreatedOnlyWhenStale(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.sock")
	l, e := Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Listen(p); e == nil {
		t.Fatal("must not replace active listener")
	}
	if e := l.Close(); e != nil {
		t.Fatal(e)
	}
	l, e = Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	_ = l.Close()
}
func TestRefusesNonSocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control.sock")
	if e := os.WriteFile(p, []byte("not a socket"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Listen(p); e == nil {
		t.Fatal("must not remove regular file")
	}
}
