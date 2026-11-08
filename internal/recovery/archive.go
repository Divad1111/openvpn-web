package recovery

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Divad1111/openvpn-web/internal/backup"
)

const maxPortableSize = 2*(backup.MaxPayload+1024) + 32768

var backupIDRegexp = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Manifest struct {
	Format        string `json:"format"`
	ID            string `json:"id"`
	CreatedAt     string `json:"createdAt"`
	AgentSHA256   string `json:"agentSHA256"`
	ManagerSHA256 string `json:"managerSHA256"`
}

type Archive struct {
	Manifest Manifest
	Manager  map[string][]byte
	Agent    map[string][]byte
}

// ReadPortable decrypts and validates all backup components before mutation.
// It MUST only be invoked by the offline recovery service; the running Web
// Manager must never decrypt Agent's private CA material.
func ReadPortable(filename, id, passphrase string) (Archive, error) {
	if !backupIDRegexp.MatchString(id) {
		return Archive{}, errors.New("invalid backup ID")
	}
	st, err := os.Lstat(filename)
	if err != nil {
		return Archive{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxPortableSize || st.Size() < 100 {
		return Archive{}, errors.New("unsafe backup file")
	}
	blob, err := os.ReadFile(filename)
	if err != nil {
		return Archive{}, err
	}
	entries := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(blob))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Archive{}, err
		}
		if h.Typeflag != tar.TypeReg || (h.Name != "manifest.json" && h.Name != "manager.seal" && h.Name != "agent.seal") || h.Size < 1 || h.Size > backup.MaxPayload+1024 {
			return Archive{}, errors.New("unexpected archive member")
		}
		if _, exists := entries[h.Name]; exists {
			return Archive{}, errors.New("duplicate archive member")
		}
		b := make([]byte, int(h.Size))
		if _, err = io.ReadFull(tr, b); err != nil {
			return Archive{}, err
		}
		entries[h.Name] = b
	}
	if len(entries) != 3 {
		return Archive{}, errors.New("incomplete archive")
	}
	var m Manifest
	if err = json.Unmarshal(entries["manifest.json"], &m); err != nil {
		return Archive{}, err
	}
	if m.Format != "openvpn-ce-manager-v1" || m.ID != id {
		return Archive{}, errors.New("invalid backup manifest")
	}
	agentHash := sha256.Sum256(entries["agent.seal"])
	managerHash := sha256.Sum256(entries["manager.seal"])
	if m.AgentSHA256 != hex.EncodeToString(agentHash[:]) || m.ManagerSHA256 != hex.EncodeToString(managerHash[:]) {
		return Archive{}, errors.New("archive digest mismatch")
	}
	managerData, err := backup.Open(entries["manager.seal"], passphrase)
	if err != nil {
		return Archive{}, err
	}
	agentData, err := backup.Open(entries["agent.seal"], passphrase)
	if err != nil {
		return Archive{}, err
	}
	for name := range managerData {
		if name != "manager/state.db" && name != "manager/master.key" {
			return Archive{}, errors.New("unexpected manager backup member")
		}
	}
	if len(managerData) != 2 || !looksSQLite(managerData["manager/state.db"]) || len(managerData["manager/master.key"]) != 32 {
		return Archive{}, errors.New("invalid manager state")
	}
	if !looksSQLite(agentData["agent/metadata.db"]) {
		return Archive{}, errors.New("invalid agent state")
	}
	for name := range agentData {
		switch {
		case name == "agent/metadata.db", name == "agent/config.json":
		case strings.HasPrefix(name, "pki/"):
		case name == "runtime/server.conf", name == "runtime/server.crt", name == "runtime/server.key", name == "runtime/ca.crt", name == "runtime/crl.pem", name == "runtime/tls-crypt.key", name == "runtime/network.json":
		default:
			return Archive{}, errors.New("unexpected agent backup member")
		}
	}
	for _, key := range []string{"pki/ca.crt", "pki/private/ca.key", "pki/issued/server.crt", "pki/private/server.key", "agent/config.json", "runtime/server.conf", "runtime/server.key", "runtime/server.crt", "runtime/ca.crt", "runtime/crl.pem", "runtime/tls-crypt.key", "runtime/network.json"} {
		if len(agentData[key]) == 0 {
			return Archive{}, fmt.Errorf("required backup member missing: %s", key)
		}
	}
	block, _ := pem.Decode(agentData["pki/ca.crt"])
	if block == nil || block.Type != "CERTIFICATE" {
		return Archive{}, errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return Archive{}, errors.New("invalid CA certificate")
	}
	if bytes.Contains(agentData["pki/private/ca.key"], []byte("BEGIN EC PRIVATE KEY")) || !bytes.Contains(agentData["pki/private/ca.key"], []byte("ENCRYPTED")) {
		return Archive{}, errors.New("CA private key is not encrypted")
	}
	if !json.Valid(agentData["agent/config.json"]) || !json.Valid(agentData["runtime/network.json"]) {
		return Archive{}, errors.New("invalid JSON config")
	}
	if !bytes.Contains(agentData["runtime/server.conf"], []byte("proto tcp-server")) {
		return Archive{}, errors.New("unexpected OpenVPN transport")
	}
	return Archive{Manifest: m, Manager: managerData, Agent: agentData}, nil
}

func looksSQLite(data []byte) bool {
	return len(data) > 100 && string(data[:16]) == "SQLite format 3\x00"
}
