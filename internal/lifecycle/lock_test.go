package lifecycle

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestLifecycleLockRejectsSecondOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state", ".running.lock")
	f, err := Hold(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Hold(p); !errors.Is(err, ErrRunning) {
		t.Fatalf("expected running: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	f2, err := Hold(p)
	if err != nil {
		t.Fatal(err)
	}
	f2.Close()
}
