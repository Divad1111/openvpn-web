package main

import (
	"flag"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/runtime/internal/supervisor"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	path := getenv("RUNTIME_SOCKET", "/run/runtime/control.sock")
	check := flag.Bool("check", false, "check runtime Unix socket")
	flag.Parse()
	if *check {
		c, e := net.DialTimeout("unix", path, time.Second)
		if e != nil {
			log.Fatal(e)
		}
		_ = c.Close()
		return
	}
	l, err := ipc.Listen(path)
	if err != nil {
		log.Fatal(err)
	}
	if err = os.Chmod(path, 0660); err != nil {
		log.Fatal(err)
	}
	log.Println("runtime supervisor: phase0 waiting for future provisioning; OpenVPN is NOT running")
	log.Fatal((&http.Server{Handler: supervisor.Handler(), ReadHeaderTimeout: 5 * time.Second}).Serve(l))
}
func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
