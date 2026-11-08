package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}
func TOTPURI(secret, username string) string {
	return "otpauth://totp/" + url.PathEscape("OpenVPN CE Manager:"+username) + "?secret=" + url.QueryEscape(secret) + "&issuer=" + url.QueryEscape("OpenVPN CE Manager") + "&algorithm=SHA1&digits=6&period=30"
}
func OTP(secret string, step int64) (string, error) {
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil || len(b) != 20 {
		return "", fmt.Errorf("invalid TOTP key")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	h := hmac.New(sha1.New, b)
	h.Write(counter[:])
	data := h.Sum(nil)
	i := int(data[len(data)-1] & 0x0f)
	code := binary.BigEndian.Uint32(data[i:i+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000), nil
}
func VerifyTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 || !isDigits(code) {
		return false
	}
	for _, v := range []int64{-1, 0, 1} {
		expected, err := OTP(secret, now.Unix()/30+v)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}
func isDigits(s string) bool { _, err := strconv.Atoi(s); return err == nil && len(s) == 6 }
