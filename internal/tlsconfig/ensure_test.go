package tlsconfig

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestEnsureBootstrapTLS(t *testing.T) {
	dir := t.TempDir()
	c, k, err := EnsureSelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tls.LoadX509KeyPair(c, k); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(k)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("private key perms %o", st.Mode().Perm())
	}
	c2, k2, err := EnsureSelfSigned(dir)
	if err != nil || c2 != c || k2 != k {
		t.Fatal("identity should be stable")
	}
}
func TestPartialTLSFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/manager.crt", []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureSelfSigned(dir); err == nil {
		t.Fatal("partial identity must fail")
	}
}
