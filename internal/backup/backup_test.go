package backup

import (
	"bytes"
	"testing"
)

func TestSealedBundleRoundtripAndTamper(t *testing.T) {
	files := map[string][]byte{"agent/pki/ca.crt": []byte("test-cert"), "agent/config.json": []byte(`{"vpnCIDR":"10.8.0.0/24"}`)}
	pass := "this-is-a-long-backup-passphrase"
	blob, err := Seal(files, pass)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("test-cert")) {
		t.Fatal("plaintext leaked")
	}
	unpacked, err := Open(blob, pass)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range files {
		if !bytes.Equal(v, unpacked[k]) {
			t.Fatalf("mismatch: %s", k)
		}
	}
	if _, err = Open(blob, "wrong-but-long-passphrase"); err == nil {
		t.Fatal("wrong key accepted")
	}
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 1
	if _, err = Open(tampered, pass); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestBackupRejectsUnsafeNamesAndWeakPassword(t *testing.T) {
	for _, n := range []string{"../etc/passwd", "/root/key", "foo/../key", "a\\b", "."} {
		if _, err := Seal(map[string][]byte{n: []byte("x")}, "long-strong-passphrase"); err == nil {
			t.Fatalf("accepted %q", n)
		}
	}
	if _, err := Seal(map[string][]byte{"okay.txt": []byte("x")}, "short"); err == nil {
		t.Fatal("accepted weak passphrase")
	}
}
