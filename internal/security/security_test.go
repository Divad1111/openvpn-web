package security

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPasswordAndSeal(t *testing.T) {
	h, err := HashPassword("supersafe-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "supersafe-password-123") || VerifyPassword(h, "wrong") {
		t.Fatal("password check failed")
	}
	key, err := MasterKey(filepath.Join(t.TempDir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	x, err := Seal(key, "MY_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	v, err := Unseal(key, x)
	if err != nil || v != "MY_SECRET" {
		t.Fatalf("unseal: %q %v", v, err)
	}
}
func TestTOTP(t *testing.T) {
	sec, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := OTP(sec, now.Unix()/30)
	if err != nil || !VerifyTOTP(sec, code, now) {
		t.Fatalf("OTP failed: %v", err)
	}
	if VerifyTOTP(sec, "0000000", now) {
		t.Fatal("invalid code accepted")
	}
}
