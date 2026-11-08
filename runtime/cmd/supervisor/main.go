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

	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/runtime/internal/supervisor"
)

func main() {
	path := getenv("RUNTIME_SOCKET", "/run/runtime/control.sock")
	check := flag.Bool("check", false, "check runtime Unix socket")
	flag.Parse()
	if *check {
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			log.Fatal(err)
		}
		_ = conn.Close()
		return
	}
	key, err := ipc.EnsureKey(getenv("RUNTIME_IPC_KEY", "/run/runtime/agent.key"), -1)
	if err != nil {
		log.Fatalf("IPC secret: %v", err)
	}
	l, err := ipc.Listen(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(path, 0660); err != nil {
		log.Fatal(err)
	}
	defer func() { l.Close(); os.Remove(path) }()
	inspect := supervisor.Inspector{
		ConfigPath: getenv("OPENVPN_CONFIG_PATH", "/etc/openvpn/server.conf"),
		TUNPath:    "/dev/net/tun", BinaryPath: "/usr/local/sbin/openvpn",
	}
	log.Println("runtime supervisor: independent OpenVPN child lifecycle")
	controller := supervisor.NewController(inspect)
	if controller.State().ConfigSafe {
		controller.AutoStart()
	}
	srv := &http.Server{Handler: controller.Handler(key), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = controller.Stop()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
