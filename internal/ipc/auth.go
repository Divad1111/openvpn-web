package ipc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	keySize      = 32
	maxBody      = 64 << 10
	maxClockSkew = 60 * time.Second
	maxNonces    = 4096
)

// EnsureKey creates a persistent per-IPC-link secret atomically. It never
// replaces a key on restart or repairs an invalid key behind an operator's back.
// The server owns its key; clients get read-only access to its directory.
func EnsureKey(path string, readableGroup int) ([]byte, error) {
	if key, err := LoadKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, keySize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".ipc-secret-")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(secret); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	if readableGroup >= 0 {
		if err = os.Chown(tmp, -1, readableGroup); err != nil {
			return nil, err
		}
	}
	if err = os.Chmod(tmp, 0640); err != nil {
		return nil, err
	}
	// Hard link gives an atomic no-replace publish; concurrent creators never overwrite.
	if err = os.Link(tmp, path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return LoadKey(path)
}

func LoadKey(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0137 != 0 {
		return nil, fmt.Errorf("unsafe IPC key type or permission: %s", path)
	}
	if st.Size() != keySize {
		return nil, fmt.Errorf("invalid IPC key length: %s", path)
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid IPC key data: %s", path)
	}
	return key, nil
}

type signedTransport struct {
	socketTransport http.RoundTripper
	keyPath         string
}

func (t signedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key, err := LoadKey(t.keyPath)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	clone := req.Clone(req.Context())
	var body []byte
	if clone.Body != nil && clone.Body != http.NoBody {
		if clone.GetBody == nil {
			return nil, errors.New("request body must be replayable for IPC signing")
		}
		reader, err := clone.GetBody()
		if err != nil {
			return nil, err
		}
		body, err = io.ReadAll(io.LimitReader(reader, maxBody+1))
		reader.Close()
		if err != nil || len(body) > maxBody {
			return nil, errors.New("IPC request body too large")
		}
	}
	nonceHex := hex.EncodeToString(nonce)
	clone.Header.Set("X-IPC-Timestamp", timestamp)
	clone.Header.Set("X-IPC-Nonce", nonceHex)
	clone.Header.Set("X-IPC-Signature", mac(key, clone.Method, clone.URL.RequestURI(), timestamp, nonceHex, body))
	return t.socketTransport.RoundTrip(clone)
}

// SignedClient signs requests over a Unix socket using an on-volume shared key.
// The key is loaded for each request to safely handle service/container recreation.
func SignedClient(socket, keyPath string) *http.Client {
	base := Client(socket)
	base.Transport = signedTransport{socketTransport: base.Transport, keyPath: keyPath}
	return base
}

func mac(key []byte, method, uri, timestamp, nonce string, body []byte) string {
	digest := sha256.Sum256(body)
	h := hmac.New(sha256.New, key)
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s", method, uri, timestamp, nonce, hex.EncodeToString(digest[:]))
	return hex.EncodeToString(h.Sum(nil))
}

type replayCache struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func (c *replayCache) add(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.used == nil {
		c.used = make(map[string]time.Time)
	}
	for n, t := range c.used {
		if now.Sub(t) > 2*maxClockSkew {
			delete(c.used, n)
		}
	}
	if _, ok := c.used[nonce]; ok || len(c.used) >= maxNonces {
		return false
	}
	c.used[nonce] = now
	return true
}

// Authenticated verifies each HTTP request's HMAC, timestamp, nonce and body;
// no route is permitted to bypass it. A fresh cache is per server instance.
func Authenticated(key []byte, next http.Handler) http.Handler {
	secret := bytes.Clone(key)
	cache := &replayCache{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		fail := func() { http.Error(w, `{"code":"IPC_UNAUTHORIZED"}`, http.StatusUnauthorized) }
		if len(secret) != keySize {
			fail()
			return
		}
		ts := r.Header.Get("X-IPC-Timestamp")
		nonce := r.Header.Get("X-IPC-Nonce")
		sig := r.Header.Get("X-IPC-Signature")
		n, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			fail()
			return
		}
		now := time.Now()
		skew := now.Sub(time.Unix(n, 0))
		if skew < -maxClockSkew || skew > maxClockSkew {
			fail()
			return
		}
		nonceBytes, err := hex.DecodeString(nonce)
		if err != nil || len(nonceBytes) != 16 || len(sig) != 64 {
			fail()
			return
		}
		signature, err := hex.DecodeString(sig)
		if err != nil {
			fail()
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(body) > maxBody {
			fail()
			return
		}
		expected, err := hex.DecodeString(mac(secret, r.Method, r.URL.RequestURI(), ts, nonce, body))
		if err != nil || !hmac.Equal(signature, expected) {
			fail()
			return
		}
		if !cache.add(nonce, now) {
			fail()
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}
