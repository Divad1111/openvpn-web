// Package lifecycle prevents an offline restore from changing database and
// private key volumes while a manager, agent or runtime service is alive.
package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var ErrRunning = errors.New("service still running: stop all three containers before recovery")

// Hold locks a persistent volume file until the process exits or Close is called.
// This is an advisory lock; it is not a substitute for Docker administrator access.
func Hold(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return nil, errors.New("unsafe lifecycle lock file")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0660)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0660); err != nil {
		f.Close()
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, fmt.Errorf("lifecycle lock failed: %w", err)
	}
	return f, nil
}

// CheckStopped must be called by the offline recovery process, on the SAME
// mounted lock files as the services. Locks stay held until restore exits.
func CheckStopped(paths ...string) ([]*os.File, error) {
	locks := make([]*os.File, 0, len(paths))
	for _, p := range paths {
		f, err := Hold(p)
		if err != nil {
			for _, lock := range locks {
				lock.Close()
			}
			return nil, err
		}
		locks = append(locks, f)
	}
	return locks, nil
}
