// A one-shot disaster recovery helper. This is NOT a fourth long-running
// service. It deliberately cannot be invoked through a Web endpoint.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Divad1111/openvpn-web/internal/policy"
	"github.com/Divad1111/openvpn-web/internal/recovery"
)

const acknowledgement = "RESTORE_ALL_OPENVPN_STATE"

func main() {
	id := flag.String("id", "", "32-character backup ID from the downloaded filename")
	archive := flag.String("archive", "", "path to .ovpnbackup under /import")
	checkOnly := flag.Bool("check-only", false, "verify the archive without altering volumes")
	apply := flag.Bool("apply", false, "perform offline restore")
	rollback := flag.Bool("rollback", false, "revert an attempted/successful offline restore")
	confirm := flag.String("confirm", "", "must equal RESTORE_ALL_OPENVPN_STATE for writes")
	flag.Parse()
	if *id == "" || (*checkOnly && (*apply || *rollback)) || (*apply && *rollback) || (!*checkOnly && !*apply && !*rollback) {
		log.Fatal("must select exactly one of --check-only, --apply, --rollback and provide --id")
	}
	roots := recovery.Roots{Manager: "/restore/manager", Agent: "/restore/agent", Runtime: "/restore/runtime", RuntimeIPC: "/restore/runtime-ipc"}
	if *apply || *rollback {
		if !policy.WriteEnabled(os.Getenv("OPENVPN_MANAGER_WRITE_ENABLED")) {
			log.Fatal("Docker write mode must be set to exact true")
		}
		if *confirm != acknowledgement {
			log.Fatal("explicit acknowledgement required")
		}
	}
	if *rollback {
		if err := recovery.Rollback(*id, roots); err != nil {
			log.Fatalf("rollback failed: %v", err)
		}
		fmt.Println("Offline rollback finished. Restart the three services and verify the state.")
		return
	}
	if *archive == "" {
		log.Fatal("--archive is required")
	}
	p, err := filepath.Abs(*archive)
	if err != nil || !strings.HasPrefix(p, "/import/") {
		log.Fatal("backup archive must reside inside /import")
	}
	fmt.Fprintln(os.Stderr, "Enter backup passphrase on standard input (not command-line arguments):")
	rd := bufio.NewReader(os.Stdin)
	password, err := rd.ReadString('\n')
	if err != nil {
		log.Fatal("failed to read passphrase from stdin")
	}
	password = strings.TrimRight(password, "\r\n")
	data, err := recovery.ReadPortable(p, *id, password)
	if err != nil {
		log.Fatalf("backup preflight failed: %v", err)
	}
	if *checkOnly {
		fmt.Printf("Validated encrypted backup %s: Manager=%d Agent=%d members. No files changed.\n", data.Manifest.ID, len(data.Manager), len(data.Agent))
		return
	}
	if err := recovery.Apply(data, roots); err != nil {
		log.Fatalf("offline restore failed: %v", err)
	}
	fmt.Printf("Offline restore %s applied. Existing data is retained in protected rollback directories.\n", data.Manifest.ID)
	fmt.Println("Start all three containers, verify operation, then clean up protected rollback copies only after an independent backup.")
}
