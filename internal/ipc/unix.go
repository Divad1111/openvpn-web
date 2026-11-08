package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

func Client(socket string) *http.Client {
	return &http.Client{Timeout: 1500 * time.Millisecond, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
		},
	}}
}

// Listen reclaims only a provably stale UNIX socket after a normal process
// restart. Never unlink non-sockets, live sockets, or inaccessible sockets.
func Listen(socket string) (net.Listener, error) {
	if socket == "" {
		return nil, errors.New("unix socket path required")
	}
	st, err := os.Lstat(socket)
	if err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("socket destination is not a socket: %s", socket)
		}
		c, dialErr := net.DialTimeout("unix", socket, 350*time.Millisecond)
		if dialErr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("active listener already owns %s", socket)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot safely reclaim socket %s: %w", socket, dialErr)
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.Listen("unix", socket)
}
