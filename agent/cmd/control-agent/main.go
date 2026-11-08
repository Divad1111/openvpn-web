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
	"github.com/Divad1111/openvpn-web/agent/internal/engine"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/internal/lifecycle"
	"github.com/Divad1111/openvpn-web/internal/policy"
	"strconv"
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
	log.Printf("control-agent: write-enabled=%v; authenticated allowlist API", mode)
	publicPort, err := strconv.Atoi(getenv("OPENVPN_PUBLIC_PORT", "1194"))
	if err != nil {
		log.Fatal("invalid public port")
	}
	lock, lockErr := lifecycle.Hold(getenv("AGENT_STATE_DIR", "/data/agent") + "/.agent-live.lock")
	if lockErr != nil {
		log.Fatalf("agent lifecycle lock: %v", lockErr)
	}
	defer lock.Close()
	eng, err := engine.New(getenv("AGENT_STATE_DIR", "/data/agent"), getenv("RUNTIME_CONFIG_DIR", "/data/runtime-config"), getenv("RUNTIME_SOCKET", "/run/runtime/control.sock"), getenv("RUNTIME_IPC_KEY", "/run/runtime/agent.key"), getenv("EASYRSA_PATH", "/opt/easy-rsa/easyrsa"), publicPort)
	if err != nil {
		log.Fatalf("engine initialize: %v", err)
	}
	defer eng.Close()
	if err := eng.ValidateRuntimeDir(); err != nil {
		log.Fatal(err)
	}
	app := &agent.API{WriteEnabled: mode, Engine: eng}
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
