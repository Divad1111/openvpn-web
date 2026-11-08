package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
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
		c, e := net.DialTimeout("unix", path, time.Second)
		if e != nil {
			log.Fatal(e)
		}
		_ = c.Close()
		return
	}
	mode := policy.WriteEnabled(os.Getenv("OPENVPN_MANAGER_WRITE_ENABLED"))
	listener, err := ipc.Listen(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(path, 0660); err != nil {
		log.Fatal(err)
	}
	log.Printf("control-agent boot: phase0, write-enabled=%v; no mutations implemented", mode)
	server := http.Server{Handler: agent.Server{WriteEnabled: mode, RuntimeSocket: getenv("RUNTIME_SOCKET", "/run/runtime/control.sock")}.Handler(), ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.Serve(listener))
}
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
