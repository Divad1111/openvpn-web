package manager

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Divad1111/openvpn-web/internal/security"
	"github.com/Divad1111/openvpn-web/internal/store"
	"log"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const sessionLifetime = 8 * time.Hour

var adminName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{2,31}$`)

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func sha(text string) string { sum := sha256.Sum256([]byte(text)); return hex.EncodeToString(sum[:]) }
func equalHash(a, b string) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type Auth struct {
	db        *store.DB
	masterKey []byte
	keyPath   string
	mu        sync.Mutex
	attempts  map[string][]time.Time
}

func OpenAuth(dbpath, masterKeypath string) (*Auth, error) {
	db, err := store.Open(dbpath)
	if err != nil {
		return nil, err
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS admins (id TEXT PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,totp_secret TEXT NOT NULL,last_step INTEGER NOT NULL DEFAULT -1,created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sessions (id_hash TEXT PRIMARY KEY,csrf_hash TEXT NOT NULL,admin_id TEXT NOT NULL,expires_at INTEGER NOT NULL,created_ip TEXT NOT NULL,FOREIGN KEY(admin_id) REFERENCES admins(id))`,
		`CREATE TABLE IF NOT EXISTS setup_state (name TEXT PRIMARY KEY,value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS setup_pending (id_hash TEXT PRIMARY KEY,username TEXT NOT NULL,password_hash TEXT NOT NULL,secret TEXT NOT NULL,expires_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,actor TEXT NOT NULL,source_ip TEXT NOT NULL,action TEXT NOT NULL,result TEXT NOT NULL,detail TEXT NOT NULL)`,
	} {
		if err = db.Exec(stmt); err != nil {
			db.Close()
			return nil, err
		}
	}
	key, err := security.MasterKey(masterKeypath)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Auth{db: db, masterKey: key, keyPath: masterKeypath, attempts: map[string][]time.Time{}}, nil
}
func (a *Auth) Close() { _ = a.db.Close() }
func (a *Auth) AdminReady() bool {
	r, err := a.db.Query(`SELECT id FROM admins LIMIT 1`)
	return err == nil && len(r) > 0
}

// EnsureBootstrap emits a raw token only once, when its SHA-256 is first stored.
// Restarting a container must not disclose it again.
func (a *Auth) EnsureBootstrap() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.AdminReady() {
		return "", nil
	}
	rows, err := a.db.Query(`SELECT value FROM setup_state WHERE name='bootstrap_hash'`)
	if err != nil {
		return "", err
	}
	if len(rows) > 0 {
		return "", nil
	}
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	if err = a.db.Exec(`INSERT INTO setup_state(name,value) VALUES('bootstrap_hash',?)`, sha(token)); err != nil {
		return "", err
	}
	return token, nil
}

var ErrUnauthorized = errors.New("invalid credentials or TOTP")
var ErrSetupAlready = errors.New("already initialized")

func (a *Auth) allowAttempt(key string) bool {
	now := time.Now()
	active := a.attempts[key][:0]
	for _, t := range a.attempts[key] {
		if now.Sub(t) < 15*time.Minute {
			active = append(active, t)
		}
	}
	if len(active) >= 8 {
		a.attempts[key] = active
		return false
	}
	a.attempts[key] = append(active, now)
	return true
}
func (a *Auth) BeginSetup(token, username, password, ip string) (challenge, uri string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowAttempt("bootstrap:" + ip) {
		return "", "", ErrUnauthorized
	}
	if a.AdminReady() {
		return "", "", ErrSetupAlready
	}
	if !adminName.MatchString(username) {
		return "", "", errors.New("username must match [A-Za-z][A-Za-z0-9_-]{2,31}")
	}
	rows, e := a.db.Query(`SELECT value FROM setup_state WHERE name='bootstrap_hash'`)
	if e != nil || len(rows) != 1 || !equalHash(rows[0]["value"], sha(token)) {
		return "", "", ErrUnauthorized
	}
	passwordHash, e := security.HashPassword(password)
	if e != nil {
		return "", "", e
	}
	sec, e := security.GenerateTOTPSecret()
	if e != nil {
		return "", "", e
	}
	enc, e := security.Seal(a.masterKey, sec)
	if e != nil {
		return "", "", e
	}
	challenge, e = randomHex(32)
	if e != nil {
		return "", "", e
	}
	if e = a.db.Exec(`DELETE FROM setup_pending`); e != nil {
		return "", "", e
	}
	if e = a.db.Exec(`INSERT INTO setup_pending(id_hash,username,password_hash,secret,expires_at) VALUES(?,?,?,?,?)`, sha(challenge), username, passwordHash, enc, strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)); e != nil {
		return "", "", e
	}
	a.Audit("bootstrap", "setup-start", ip, "accepted", "")
	return challenge, security.TOTPURI(sec, username), nil
}
func (a *Auth) FinishSetup(challenge, otp, ip string) (username string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowAttempt("setup-finish:" + ip) {
		return "", ErrUnauthorized
	}
	if a.AdminReady() {
		return "", ErrSetupAlready
	}
	rows, e := a.db.Query(`SELECT username,password_hash,secret,expires_at FROM setup_pending WHERE id_hash=?`, sha(challenge))
	if e != nil || len(rows) != 1 {
		return "", ErrUnauthorized
	}
	row := rows[0]
	deadline, _ := strconv.ParseInt(row["expires_at"], 10, 64)
	if time.Now().Unix() > deadline {
		return "", ErrUnauthorized
	}
	sec, e := security.Unseal(a.masterKey, row["secret"])
	if e != nil || !security.VerifyTOTP(sec, otp, time.Now()) {
		return "", ErrUnauthorized
	}
	id, e := randomHex(16)
	if e != nil {
		return "", e
	}
	err = a.db.Transaction(func(tx *store.Tx) error {
		if e := tx.Exec(`INSERT INTO admins(id,username,password_hash,totp_secret,created_at) VALUES(?,?,?,?,?)`, id, row["username"], row["password_hash"], row["secret"], time.Now().UTC().Format(time.RFC3339)); e != nil {
			return e
		}
		if e := tx.Exec(`DELETE FROM setup_pending`); e != nil {
			return e
		}
		return tx.Exec(`DELETE FROM setup_state WHERE name='bootstrap_hash'`)
	})
	if err != nil {
		return "", err
	}
	a.Audit(row["username"], "setup-finish", ip, "success", "")
	return row["username"], nil
}

type Session struct {
	Username, IDHash, CSRF string
	Expires                time.Time
}

func (a *Auth) Login(username, password, otp, ip string) (token string, session Session, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowAttempt("login:" + username + ":" + ip) {
		return "", session, ErrUnauthorized
	}
	rows, e := a.db.Query(`SELECT id,username,password_hash,totp_secret FROM admins WHERE username=?`, username)
	if e != nil || len(rows) != 1 {
		return "", session, ErrUnauthorized
	}
	row := rows[0]
	if !security.VerifyPassword(row["password_hash"], password) {
		return "", session, ErrUnauthorized
	}
	secret, e := security.Unseal(a.masterKey, row["totp_secret"])
	if e != nil || !security.VerifyTOTP(secret, otp, time.Now()) {
		return "", session, ErrUnauthorized
	}
	token, e = randomHex(32)
	if e != nil {
		return "", session, e
	}
	csrf, e := randomHex(32)
	if e != nil {
		return "", session, e
	}
	exp := time.Now().Add(sessionLifetime)
	e = a.db.Exec(`INSERT INTO sessions(id_hash,csrf_hash,admin_id,expires_at,created_ip) VALUES(?,?,?,?,?)`, sha(token), sha(csrf), row["id"], strconv.FormatInt(exp.Unix(), 10), ip)
	if e != nil {
		return "", session, e
	}
	a.Audit(username, "login", ip, "success", "")
	return token, Session{Username: username, IDHash: sha(token), CSRF: csrf, Expires: exp}, nil
}
func (a *Auth) Check(token string) (Session, bool) {
	if len(token) != 64 {
		return Session{}, false
	}
	rows, e := a.db.Query(`SELECT a.username AS username,s.expires_at AS expires_at,s.id_hash AS id_hash FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.id_hash=?`, sha(token))
	if e != nil || len(rows) != 1 {
		return Session{}, false
	}
	exp, e := strconv.ParseInt(rows[0]["expires_at"], 10, 64)
	if e != nil || time.Now().Unix() > exp {
		return Session{}, false
	}
	return Session{Username: rows[0]["username"], IDHash: rows[0]["id_hash"], Expires: time.Unix(exp, 0)}, true
}
func (a *Auth) CheckCSRF(sess Session, csrf string) bool {
	rows, e := a.db.Query(`SELECT csrf_hash FROM sessions WHERE id_hash=?`, sess.IDHash)
	return e == nil && len(rows) == 1 && equalHash(rows[0]["csrf_hash"], sha(csrf))
}
func (a *Auth) RefreshCSRF(sess Session) (string, error) {
	token, e := randomHex(32)
	if e != nil {
		return "", e
	}
	if e = a.db.Exec(`UPDATE sessions SET csrf_hash=? WHERE id_hash=?`, sha(token), sess.IDHash); e != nil {
		return "", e
	}
	return token, nil
}
func (a *Auth) VerifyAdminTOTP(username, otp string) bool {
	rows, err := a.db.Query(`SELECT totp_secret FROM admins WHERE username=?`, username)
	if err != nil || len(rows) != 1 {
		return false
	}
	sec, err := security.Unseal(a.masterKey, rows[0]["totp_secret"])
	return err == nil && security.VerifyTOTP(sec, otp, time.Now())
}
func (a *Auth) Logout(sess Session) error {
	return a.db.Exec(`DELETE FROM sessions WHERE id_hash=?`, sess.IDHash)
}
func (a *Auth) Audit(actor, action, ip, result, detail string) {
	if len(detail) > 256 {
		detail = detail[:256]
	}
	if err := a.db.Exec(`INSERT INTO audit_logs(created_at,actor,source_ip,action,result,detail) VALUES(?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339), actor, ip, action, result, detail); err != nil {
		log.Printf("audit persistence error: %v", err)
	}
}
func (a *Auth) Audits() ([]map[string]string, error) {
	return a.db.Query(`SELECT created_at,actor,source_ip,action,result,detail FROM audit_logs ORDER BY id DESC LIMIT 100`)
}
func (a *Auth) String() string { return fmt.Sprintf("admins-ready=%t", a.AdminReady()) }
