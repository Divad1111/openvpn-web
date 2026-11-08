package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Divad1111/openvpn-web/backend/internal/manager"
	"github.com/Divad1111/openvpn-web/internal/policy"
	"github.com/Divad1111/openvpn-web/internal/tlsconfig"
)

func main() {
	check := flag.Bool("check", false, "check local HTTPS port (readiness)")
	flag.Parse()
	if *check {
		c, err := net.DialTimeout("tcp", "127.0.0.1:9443", time.Second)
		if err != nil {
			log.Fatal(err)
		}
		_ = c.Close()
		return
	}
	cert, key, err := tlsconfig.EnsureSelfSigned(getenv("MANAGER_TLS_DIR", "/data/manager/tls"))
	if err != nil {
		log.Fatalf("https identity: %v", err)
	}
	mode := policy.WriteEnabled(os.Getenv("OPENVPN_MANAGER_WRITE_ENABLED"))
	log.Printf("manager boot: phase0, write-enabled=%v, HTTPS bootstrap certificate", mode)
	h := manager.Server{WriteEnabled: mode, AgentSocket: getenv("AGENT_SOCKET", "/run/agent/control.sock"), WebDir: getenv("WEB_DIR", "/app/web")}
	server := &http.Server{Addr: ":9443", Handler: h.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	if err := server.ListenAndServeTLS(cert, key); err != nil {
		log.Fatal(err)
	}
}
func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
