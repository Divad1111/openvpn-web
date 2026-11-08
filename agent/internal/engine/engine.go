package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"github.com/Divad1111/openvpn-web/internal/store"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	mu                                              sync.Mutex
	DB                                              *store.DB
	PKI                                             PKI
	AgentDir, RuntimeDir, RuntimeSocket, RuntimeKey string
	PublicPort                                      int
}

func New(root, runtime, socket, key, easyrsa string, port int) (*Engine, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid public port")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	db, err := store.Open(filepath.Join(root, "metadata.db"))
	if err != nil {
		return nil, err
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,name TEXT UNIQUE NOT NULL,serial TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,status TEXT NOT NULL,exported INTEGER NOT NULL DEFAULT 0,issued_at TEXT NOT NULL,revoked_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS configurations(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,content_hash TEXT NOT NULL,status TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,event TEXT NOT NULL,target TEXT NOT NULL,status TEXT NOT NULL)`,
	} {
		if err = db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Engine{DB: db, AgentDir: root, RuntimeDir: runtime, RuntimeSocket: socket, RuntimeKey: key, PublicPort: port, PKI: PKI{Dir: filepath.Join(root, "pki"), EasyRSA: easyrsa, PassTmpDir: "/run/ca-pass"}}, nil
}
func (e *Engine) Close() { _ = e.DB.Close() }
func (e *Engine) Config() (Config, error) {
	return ReadConfig(filepath.Join(e.AgentDir, "config.json"))
}
func (e *Engine) Audit(event, target, status string) {
	_ = e.DB.Exec(`INSERT INTO audit(created_at,event,target,status) VALUES(?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), event, target, status)
}
func (e *Engine) RuntimeCall(method, path string, payload any) (json.RawMessage, int, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://runtime"+path, body)
	if err != nil {
		return nil, 0, err
	}
	client := ipc.SignedClient(e.RuntimeSocket, e.RuntimeKey)
	client.Timeout = 15 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return b, resp.StatusCode, err
}
func (e *Engine) InitPKI(ctx context.Context, pass string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.PKI.Init(ctx, pass); err != nil {
		e.Audit("pki-init", "CA", "failed")
		return err
	}
	e.Audit("pki-init", "CA", "success")
	return nil
}
func (e *Engine) Clients() ([]map[string]string, error) {
	return e.DB.Query(`SELECT id,name,serial,expires_at,status,exported,issued_at,COALESCE(revoked_at,'') AS revoked_at FROM clients ORDER BY issued_at DESC`)
}
func (e *Engine) CreateClient(ctx context.Context, name, pass string, days int) (map[string]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.Config(); err != nil {
		return nil, errors.New("VPN must be configured first")
	}
	rows, err := e.DB.Query(`SELECT id FROM clients WHERE name=?`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		return nil, errors.New("client name already exists")
	}
	if err = e.PKI.IssueClient(ctx, pass, name, days); err != nil {
		e.Audit("issue", name, "failed")
		return nil, err
	}
	cert, err := e.PKI.Certificate(name)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(cert.SerialNumber.Bytes())
	if len(id) > 64 {
		return nil, errors.New("certificate serial too long")
	}
	out := map[string]string{"id": id, "name": name, "serial": cert.SerialNumber.Text(16), "status": "ACTIVE", "expiresAt": cert.NotAfter.UTC().Format(time.RFC3339)}
	err = e.DB.Exec(`INSERT INTO clients(id,name,serial,expires_at,status,exported,issued_at) VALUES(?,?,?,?,?,0,?)`, id, name, cert.SerialNumber.Text(16), out["expiresAt"], "ACTIVE", time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	e.Audit("issue", name, "success")
	return out, nil
}
func (e *Engine) ExportClient(id string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.DB.Query(`SELECT name,exported,status FROM clients WHERE id=?`, id)
	if err != nil || len(rows) != 1 {
		return "", errors.New("client not found")
	}
	if rows[0]["status"] != "ACTIVE" || rows[0]["exported"] != "0" {
		return "", errors.New("private profile already exported or revoked")
	}
	conf, err := e.Config()
	if err != nil {
		return "", err
	}
	profile, err := e.PKI.Profile(conf, rows[0]["name"])
	if err != nil {
		return "", err
	}
	profile = strings.Replace(profile, "remote "+conf.PublicHost+" 1194\n", fmt.Sprintf("remote %s %d\n", conf.PublicHost, e.PublicPort), 1)
	if err = e.DB.Exec(`UPDATE clients SET exported=1 WHERE id=? AND exported=0`, id); err != nil {
		return "", err
	}
	e.Audit("export-profile", rows[0]["name"], "success")
	return profile, nil
}
func (e *Engine) RevokeClient(ctx context.Context, id, pass string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rows, err := e.DB.Query(`SELECT name,status FROM clients WHERE id=?`, id)
	if err != nil || len(rows) != 1 {
		return errors.New("client not found")
	}
	row := rows[0]
	if row["status"] != "ACTIVE" && row["status"] != "REVOKE_PENDING" {
		return errors.New("client not active")
	}
	if row["status"] == "ACTIVE" {
		if err = e.PKI.Revoke(ctx, pass, row["name"]); err != nil {
			e.Audit("revoke", row["name"], "failed")
			return err
		}
		if err = e.DB.Exec(`UPDATE clients SET status='REVOKE_PENDING' WHERE id=?`, id); err != nil {
			return err
		}
	}
	if err = e.PKI.GenerateCRL(ctx, pass); err != nil {
		return err
	}
	crl, err := os.ReadFile(filepath.Join(e.PKI.Dir, "crl.pem"))
	if err != nil {
		return err
	}
	if err = AtomicFile(filepath.Join(e.RuntimeDir, "crl.pem"), crl, 0640); err != nil {
		return err
	}
	// A CRL update alone is not enough for a connected client. If the runtime
	// cannot be reached or the client cannot be kicked, keep REVOKE_PENDING.
	connections, code, err := e.RuntimeCall(http.MethodGet, "/v1/connections", nil)
	if err != nil || code != 200 {
		return errors.New("CRL published but runtime connection status unavailable; revocation pending verification")
	}
	online := bytes.Contains(connections, []byte(`"commonName":"`+row["name"]+`"`))
	if online {
		_, kickStatus, kickErr := e.RuntimeCall(http.MethodPost, "/v1/kick", map[string]string{"commonName": row["name"]})
		if kickErr != nil || kickStatus != 200 {
			return errors.New("CRL published but existing client session could not be disconnected")
		}
	}
	if err = e.DB.Exec(`UPDATE clients SET status='REVOKED',revoked_at=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339), id); err != nil {
		return err
	}
	e.Audit("revoke", row["name"], "success")
	return nil
}
func (e *Engine) ApplyConfig(c Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	content, err := Render(c)
	if err != nil {
		return err
	}
	if !e.PKI.exists() {
		return errors.New("PKI not initialized")
	}
	// Preflight and snapshot of existing files; never overwrite CA private key.
	files := map[string]string{"server.conf": "", "ca.crt": "ca.crt", "server.crt": "issued/server.crt", "server.key": "private/server.key", "crl.pem": "crl.pem", "tls-crypt.key": "tls-crypt.key"}
	next := map[string][]byte{"server.conf": []byte(content)}
	next["network.json"], _ = json.Marshal(map[string]string{"vpnCIDR": c.VPNCIDR, "lanCIDR": c.LANCIDR})
	for dest, src := range files {
		if dest == "server.conf" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(e.PKI.Dir, src))
		if err != nil {
			return err
		}
		next[dest] = b
	}
	before := map[string][]byte{}
	oldConfig, previousConfigErr := os.ReadFile(filepath.Join(e.AgentDir, "config.json"))
	if previousConfigErr != nil && !os.IsNotExist(previousConfigErr) {
		return previousConfigErr
	}
	revert := func() {
		e.rollback(before, next)
		if previousConfigErr == nil {
			_ = AtomicFile(filepath.Join(e.AgentDir, "config.json"), oldConfig, 0600)
		} else {
			_ = os.Remove(filepath.Join(e.AgentDir, "config.json"))
		}
	}
	for dest := range next {
		b, err := os.ReadFile(filepath.Join(e.RuntimeDir, dest))
		if err == nil {
			before[dest] = b
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	// Only update runtime with pre-validated files. A failed deployment rolls back.
	for dest, b := range next {
		if err = AtomicFile(filepath.Join(e.RuntimeDir, dest), b, 0640); err != nil {
			revert()
			return err
		}
	}
	cfgbytes, _ := json.MarshalIndent(c, "", "  ")
	if err = AtomicFile(filepath.Join(e.AgentDir, "config.json"), cfgbytes, 0600); err != nil {
		revert()
		return err
	}
	// If Runtime is unavailable, don't silently report successful application.
	runtime, code, callErr := e.RuntimeCall(http.MethodGet, "/v1/status", nil)
	if callErr != nil || code != 200 {
		revert()
		return errors.New("runtime IPC unavailable")
	}
	running := bytes.Contains(runtime, []byte(`"running":true`))
	action := "/v1/start"
	if running {
		action = "/v1/reload"
	}
	_, code, callErr = e.RuntimeCall(http.MethodPost, action, nil)
	if callErr != nil || code != 200 {
		revert()
		if running {
			_, _, _ = e.RuntimeCall(http.MethodPost, "/v1/reload", nil)
		}
		return errors.New("OpenVPN rejected new configuration")
	}
	healthy := false
	for i := 0; i < 20; i++ {
		time.Sleep(250 * time.Millisecond)
		data, c, err := e.RuntimeCall(http.MethodGet, "/v1/status", nil)
		if err == nil && c == 200 && bytes.Contains(data, []byte(`"running":true`)) {
			healthy = true
			break
		}
	}
	if !healthy {
		revert()
		if running {
			_, _, _ = e.RuntimeCall(http.MethodPost, "/v1/reload", nil)
		} else {
			_, _, _ = e.RuntimeCall(http.MethodPost, "/v1/stop", nil)
		}
		return errors.New("OpenVPN did not become healthy after applying config")
	}

	hash := sha256.Sum256([]byte(content))
	_ = e.DB.Exec(`INSERT INTO configurations(created_at,content_hash,status) VALUES(?,?,?)`, time.Now().UTC().Format(time.RFC3339), hex.EncodeToString(hash[:]), "APPLIED")
	e.Audit("config-apply", c.PublicHost, "success")
	return nil
}
func (e *Engine) rollback(before map[string][]byte, next map[string][]byte) {
	for dest := range next {
		path := filepath.Join(e.RuntimeDir, dest)
		if old, ok := before[dest]; ok {
			_ = AtomicFile(path, old, 0640)
		} else {
			_ = os.Remove(path)
		}
	}
}
func (e *Engine) Backups() ([]map[string]string, error) {
	return e.DB.Query(`SELECT created_at,content_hash,status FROM configurations ORDER BY id DESC LIMIT 20`)
}
func (e *Engine) AuditTrail() ([]map[string]string, error) {
	return e.DB.Query(`SELECT created_at,event,target,status FROM audit ORDER BY id DESC LIMIT 100`)
}
func (e *Engine) ValidateRuntimeDir() error {
	dir := filepath.Clean(e.RuntimeDir)
	if dir == "/" || dir == "." {
		return errors.New("unsafe runtime directory")
	}
	return os.MkdirAll(dir, 0750)
}
func (e *Engine) Revision() string {
	r, _ := e.DB.Query(`SELECT id FROM configurations ORDER BY id DESC LIMIT 1`)
	if len(r) == 0 {
		return "0"
	}
	i, _ := strconv.Atoi(r[0]["id"])
	return strconv.Itoa(i)
}

func (e *Engine) PKIReady() bool { return e.PKI.exists() }
