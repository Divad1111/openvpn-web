package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Divad1111/openvpn-web/agent/internal/agent"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/internal/policy"
)

func main() {
	path := getenv("AGENT_SOCKET", "/run/agent/control.sock")
	check := flag.Bool("check", false, "verify local Unix socket is accepting connections")
	flag.Parse()
	if *check {
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			log.Fatal(err)
		}
		_ = conn.Close()
		return
	}
	secret, err := ipc.EnsureKey(getenv("AGENT_IPC_KEY", "/run/agent/manager.key"), -1)
	if err != nil {
		log.Fatalf("IPC secret: %v", err)
	}
	mode := policy.WriteEnabled(os.Getenv("OPENVPN_MANAGER_WRITE_ENABLED"))
	listener, err := ipc.Listen(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(path, 0660); err != nil {
		log.Fatal(err)
	}
	defer func() { listener.Close(); os.Remove(path) }()
	log.Printf("control-agent phase1: write-enabled=%v; all mutations disabled pending Phase 2", mode)
	app := agent.Server{WriteEnabled: mode, RuntimeSocket: getenv("RUNTIME_SOCKET", "/run/runtime/control.sock"), RuntimeKeyPath: getenv("RUNTIME_IPC_KEY", "/run/runtime/agent.key")}
	srv := &http.Server{Handler: app.Handler(secret), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err = srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
