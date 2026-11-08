// Package backup provides a bounded, authenticated, passphrase-encrypted bundle
// for protected VPN configuration and identity data. Encryption is mandatory.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/Divad1111/openvpn-web/internal/security"
)

const MaxPayload = 48 << 20
const magic = "OVPNCEBAK\x01"

// Seal includes no plaintext metadata. A new random salt and AEAD nonce are
// generated per backup. The passphrase must never be logged or persisted.
func Seal(files map[string][]byte, passphrase string) ([]byte, error) {
	if len(files) == 0 {
		return nil, errors.New("empty backup")
	}
	names := make([]string, 0, len(files))
	total := 0
	for name, content := range files {
		if err := checkName(name); err != nil {
			return nil, err
		}
		total += len(content)
		if total > MaxPayload || len(files) > 8192 {
			return nil, errors.New("backup exceeds size limits")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		content := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if raw.Len() > MaxPayload {
		return nil, errors.New("compressed backup exceeds size limits")
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := security.DeriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Header is bound as associated data to prevent format/metadata tampering.
	head := append(append([]byte(magic), salt...), nonce...)
	out := make([]byte, 0, len(head)+raw.Len()+aead.Overhead())
	out = append(out, head...)
	out = aead.Seal(out, nonce, raw.Bytes(), head)
	return out, nil
}

// Open authenticates *before* opening any individual entries. No output is
// written to disk until a caller validates all required files.
func Open(blob []byte, passphrase string) (map[string][]byte, error) {
	headLen := len(magic) + 16 + 12
	if len(blob) < headLen+16 || len(blob) > MaxPayload+headLen+64 {
		return nil, errors.New("invalid backup size")
	}
	if string(blob[:len(magic)]) != magic {
		return nil, errors.New("unsupported backup format")
	}
	salt := blob[len(magic) : len(magic)+16]
	nonce := blob[len(magic)+16 : headLen]
	key, err := security.DeriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, blob[headLen:], blob[:headLen])
	if err != nil {
		return nil, errors.New("invalid backup passphrase or authentication tag")
	}
	zr, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(io.LimitReader(zr, MaxPayload+1024))
	files := map[string][]byte{}
	used := int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return nil, errors.New("nonregular archive entry")
		}
		if err = checkName(h.Name); err != nil {
			return nil, err
		}
		if _, exists := files[h.Name]; exists {
			return nil, errors.New("duplicate archive entry")
		}
		if h.Size < 0 || h.Size > MaxPayload || used+h.Size > MaxPayload {
			return nil, errors.New("archive exceeds size limits")
		}
		b := make([]byte, int(h.Size))
		if _, err = io.ReadFull(tr, b); err != nil {
			return nil, err
		}
		files[h.Name] = b
		used += h.Size
		if len(files) > 8192 {
			return nil, errors.New("too many archive entries")
		}
	}
	if len(files) == 0 {
		return nil, errors.New("empty archive")
	}
	return files, nil
}

func checkName(name string) error {
	if name == "" || len(name) > 255 || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return fmt.Errorf("unsafe backup entry name")
	}
	return nil
}

func VerifyHeader(b []byte) error {
	if len(b) < len(magic)+16+12+16 || string(b[:len(magic)]) != magic {
		return errors.New("invalid backup header")
	}
	return nil
}

// Prefix is for offline tooling only; no timestamps or identities are exposed.
func Version() uint32 { return binary.BigEndian.Uint32([]byte{0, 0, 0, 1}) }
