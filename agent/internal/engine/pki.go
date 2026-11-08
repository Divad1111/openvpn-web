package engine

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var clientPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{1,63}$`)

type PKI struct{ Dir, EasyRSA, PassTmpDir string }

func (p PKI) exists() bool { _, err := os.Stat(filepath.Join(p.Dir, "ca.crt")); return err == nil }
func (p PKI) withPass(ctx context.Context, pass string, fn func(string) error) error {
	if len(pass) < 16 || len(pass) > 512 {
		return errors.New("CA passphrase must be 16 to 512 chars")
	}
	if err := os.MkdirAll(p.PassTmpDir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(p.PassTmpDir, "ca-pass-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.WriteString(pass + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return fn(tmp)
}
func (p PKI) run(ctx context.Context, passfile string, args ...string) error {
	// Explicit executable + argument vector, never /bin/sh -c or user-provided paths.
	a := []string{"--batch"}
	if passfile != "" {
		a = append(a, "--passin=file:"+passfile)
	}
	a = append(a, args...)
	cmd := exec.CommandContext(ctx, p.EasyRSA, a...)
	cmd.Env = append(os.Environ(), "EASYRSA_PKI="+p.Dir, "EASYRSA_REQ_CN=OpenVPN-CE-Manager-CA", "EASYRSA_ALGO=ec", "EASYRSA_CURVE=secp384r1", "EASYRSA_BATCH=1", "EASYRSA_CRL_DAYS=365")
	// Deliberately omit combined stderr which can include tool prompts or secrets.
	out, err := cmd.Output()
	_ = out
	if err != nil {
		return fmt.Errorf("Easy-RSA operation failed: %w", err)
	}
	return nil
}
func (p PKI) Init(ctx context.Context, pass string) error {
	if p.exists() {
		return errors.New("CA already initialized")
	}
	if entries, err := os.ReadDir(p.Dir); err == nil && len(entries) > 0 {
		return errors.New("nonempty PKI directory cannot be reinitialized")
	}
	if err := os.MkdirAll(filepath.Dir(p.Dir), 0700); err != nil {
		return err
	}
	if err := p.run(ctx, "", "init-pki"); err != nil {
		return err
	}
	if err := p.withPass(ctx, pass, func(file string) error {
		// passout is a file descriptor pathname, never a CLI literal secret.
		// Easy-RSA's encrypted build-ca requires both passin and passout.
		// OpenSSL rejects the same file name for both options; use two
		// separate 0600 files in the isolated /run/ca-pass tmpfs.
		passCopy := file + "-passout"
		original, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if err := os.WriteFile(passCopy, original, 0600); err != nil {
			return err
		}
		defer os.Remove(passCopy)
		a := []string{"--batch", "--passin=file:" + file, "--passout=file:" + passCopy, "build-ca"}
		cmd := exec.CommandContext(ctx, p.EasyRSA, a...)
		cmd.Env = append(os.Environ(), "EASYRSA_PKI="+p.Dir, "EASYRSA_REQ_CN=OpenVPN-CE-Manager-CA", "EASYRSA_ALGO=ec", "EASYRSA_CURVE=secp384r1", "EASYRSA_BATCH=1")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build-ca failed: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	if !p.exists() {
		return errors.New("CA certificate was not generated")
	}
	if err := p.IssueServer(ctx, pass); err != nil {
		return err
	}
	if err := p.GenerateCRL(ctx, pass); err != nil {
		return err
	}
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	hexkey := hex.EncodeToString(key)
	for i := 0; i < len(hexkey); i += 32 {
		b.WriteString(hexkey[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return AtomicFile(filepath.Join(p.Dir, "tls-crypt.key"), []byte(b.String()), 0600)
}
func (p PKI) IssueServer(ctx context.Context, pass string) error {
	return p.withPass(ctx, pass, func(tmp string) error { return p.run(ctx, tmp, "build-server-full", "server", "nopass") })
}
func (p PKI) IssueClient(ctx context.Context, pass, name string, days int) error {
	if !clientPattern.MatchString(name) || name == "server" || name == "ca" {
		return errors.New("invalid client name")
	}
	if days < 30 || days > 825 {
		return errors.New("certificate days must be 30..825")
	}
	if _, err := os.Stat(filepath.Join(p.Dir, "issued", name+".crt")); err == nil {
		return errors.New("client certificate exists")
	}
	return p.withPass(ctx, pass, func(tmp string) error {
		return p.run(ctx, tmp, "--days="+strconv.Itoa(days), "build-client-full", name, "nopass")
	})
}
func (p PKI) Revoke(ctx context.Context, pass, name string) error {
	if !clientPattern.MatchString(name) {
		return errors.New("invalid client name")
	}
	return p.withPass(ctx, pass, func(tmp string) error { return p.run(ctx, tmp, "revoke-issued", name) })
}
func (p PKI) GenerateCRL(ctx context.Context, pass string) error {
	return p.withPass(ctx, pass, func(tmp string) error { return p.run(ctx, tmp, "--days=365", "gen-crl") })
}
func (p PKI) Certificate(name string) (*x509.Certificate, error) {
	if !clientPattern.MatchString(name) {
		return nil, errors.New("invalid certificate name")
	}
	b, err := os.ReadFile(filepath.Join(p.Dir, "issued", name+".crt"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid X509 PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
func (p PKI) Profile(c Config, name string) (string, error) {
	if !clientPattern.MatchString(name) {
		return "", errors.New("invalid client name")
	}
	cert, err := p.Certificate(name)
	if err != nil {
		return "", err
	}
	if time.Now().After(cert.NotAfter) {
		return "", errors.New("expired certificate")
	}
	files := []struct{ Tag, Name string }{{"ca", "ca.crt"}, {"cert", filepath.Join("issued", name+".crt")}, {"key", filepath.Join("private", name+".key")}, {"tls-crypt", "tls-crypt.key"}}
	var b strings.Builder
	b.WriteString("client\ndev tun\nproto tcp-client\n")
	fmt.Fprintf(&b, "remote %s 1194\n", c.PublicHost)
	b.WriteString("nobind\npersist-key\npersist-tun\nremote-cert-tls server\n")
	b.WriteString("data-ciphers AES-256-GCM:AES-128-GCM\nverb 3\n")
	for _, f := range files {
		content, err := os.ReadFile(filepath.Join(p.Dir, f.Name))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", f.Tag, strings.TrimSpace(string(content)), f.Tag)
	}
	return b.String(), nil
}
