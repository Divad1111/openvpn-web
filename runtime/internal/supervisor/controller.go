package supervisor

import (
	"bufio"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Divad1111/openvpn-web/internal/ipc"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Controller is the sole process supervisor for the OpenVPN child. It never
// spawns a shell and accepts only allowlisted operations on fixed filesystem paths.
type Controller struct {
	Inspector
	mu               sync.Mutex
	proc             *exec.Cmd
	running          bool
	lastError        string
	ManagementSocket string
	StatusFile       string
	activeRules      []rule
	managementPass   string
}

func NewController(i Inspector) *Controller {
	return &Controller{Inspector: i, ManagementSocket: "/run/openvpn/management.sock", StatusFile: "/run/openvpn/status.log"}
}
func (c *Controller) State() Status {
	s := c.Inspect()
	c.mu.Lock()
	s.Running = c.running
	s.Diagnostics = append(s.Diagnostics, c.lastError)
	if c.running {
		s.State = "RUNNING"
		s.Phase = "PHASE_3_RUNTIME"
	} else if s.ConfigSafe {
		s.State = "READY_STOPPED"
	}
	c.mu.Unlock()
	return s
}
func (c *Controller) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return nil
	}
	check := c.Inspect()
	if !check.TUNAvailable || !check.BinaryAvailable || !check.ConfigSafe {
		return fmt.Errorf("runtime preflight failed: %s", strings.Join(check.Diagnostics, "; "))
	}
	if err := os.MkdirAll(filepath.Dir(c.ManagementSocket), 0700); err != nil {
		return err
	}
	// The management interface password exists only in the runtime container.
	if c.managementPass == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		c.managementPass = hex.EncodeToString(b)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(c.ManagementSocket), "management.pass"), []byte(c.managementPass+"\n"), 0600); err != nil {
		return err
	}
	if err := c.applyNetwork(); err != nil {
		c.clearNetwork()
		c.lastError = err.Error()
		return err
	}
	cmd := exec.Command(c.BinaryPath, "--config", c.ConfigPath)
	cmd.Dir = "/etc/openvpn"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		c.clearNetwork()
		c.lastError = err.Error()
		return err
	}
	c.proc = cmd
	c.running = true
	c.lastError = ""
	go func() {
		err := cmd.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.proc == cmd {
			c.clearNetwork()
			c.running = false
			c.proc = nil
			if err != nil {
				c.lastError = fmt.Sprintf("OpenVPN process exited: %v", err)
			}
		}
	}()
	return nil
}
func (c *Controller) Stop() error {
	c.mu.Lock()
	proc := c.proc
	running := c.running
	c.mu.Unlock()
	if !running || proc == nil {
		return nil
	}
	if err := proc.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	end := time.Now().Add(8 * time.Second)
	for time.Now().Before(end) {
		c.mu.Lock()
		alive := c.running
		c.mu.Unlock()
		if !alive {
			c.mu.Lock()
			c.clearNetwork()
			c.mu.Unlock()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = proc.Process.Kill()
	return errors.New("OpenVPN did not exit within timeout, terminated")
}
func (c *Controller) Reload() error {
	c.mu.Lock()
	running := c.running
	c.mu.Unlock()
	if !running {
		return errors.New("OpenVPN not running")
	}
	if err := c.Stop(); err != nil {
		return err
	}
	return c.Start()
}

var clientID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (c *Controller) Kick(client string) error {
	if !clientID.MatchString(client) {
		return errors.New("invalid client CN")
	}
	return c.management("kill " + client)
}
func (c *Controller) management(command string) error {
	conn, err := net.DialTimeout("unix", c.ManagementSocket, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// The management socket is confined to 0700 /run/openvpn in the runtime
	// container and never shared with Manager or Agent. It uses no TCP listener.
	rd := bufio.NewReader(conn)
	line, err := rd.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "OpenVPN Management Interface") {
		return errors.New("unexpected management greeting")
	}
	if _, err = fmt.Fprintf(conn, "%s\n%s\nquit\n", c.managementPass, command); err != nil {
		return err
	}
	for i := 0; i < 15; i++ {
		line, err = rd.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "SUCCESS:") {
			return nil
		}
		if strings.HasPrefix(line, "ERROR:") {
			return errors.New("management command rejected")
		}
	}
	return errors.New("management command not acknowledged")
}

// Connections parses the status 3 CSV file and exposes only connection metadata;
// it never logs client traffic or private key material.
func (c *Controller) Connections() ([]map[string]any, error) {
	f, err := os.Open(c.StatusFile)
	if os.IsNotExist(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0)
	for _, r := range records {
		if len(r) >= 12 && r[0] == "CLIENT_LIST" {
			in, _ := strconv.ParseInt(r[5], 10, 64)
			outb, _ := strconv.ParseInt(r[6], 10, 64)
			out = append(out, map[string]any{"commonName": r[1], "realAddress": r[2], "virtualAddress": r[3], "bytesReceived": in, "bytesSent": outb, "connectedSince": r[7]})
		}
	}
	return out, nil
}
func (c *Controller) Handler(key []byte) http.Handler {
	mux := http.NewServeMux()
	respond := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, c.State()) })
	mux.HandleFunc("GET /v1/connections", func(w http.ResponseWriter, r *http.Request) {
		rows, err := c.Connections()
		if err != nil {
			respond(w, 500, map[string]string{"code": "STATUS_UNAVAILABLE"})
			return
		}
		respond(w, 200, map[string]any{"connections": rows})
	})
	mux.HandleFunc("POST /v1/start", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Start(); err != nil {
			respond(w, 409, map[string]string{"code": "RUNTIME_START_FAILED"})
			return
		}
		respond(w, 200, c.State())
	})
	mux.HandleFunc("POST /v1/stop", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Stop(); err != nil {
			respond(w, 500, map[string]string{"code": "RUNTIME_STOP_FAILED"})
			return
		}
		respond(w, 200, c.State())
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Reload(); err != nil {
			respond(w, 409, map[string]string{"code": "RUNTIME_RELOAD_FAILED"})
			return
		}
		respond(w, 200, c.State())
	})
	mux.HandleFunc("POST /v1/kick", func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			CommonName string `json:"commonName"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil || !clientID.MatchString(v.CommonName) {
			respond(w, 400, map[string]string{"code": "INVALID_CLIENT"})
			return
		}
		if err := c.Kick(v.CommonName); err != nil {
			respond(w, 409, map[string]string{"code": "KICK_FAILED"})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 404, map[string]string{"code": "UNKNOWN_OPERATION"})
	})
	return ipc.Authenticated(key, mux)
}
func (c *Controller) AutoStart() {
	if err := c.Start(); err != nil {
		c.mu.Lock()
		c.lastError = err.Error()
		c.mu.Unlock()
	}
}
