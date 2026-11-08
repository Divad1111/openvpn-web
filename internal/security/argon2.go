package security

/*
#cgo linux LDFLAGS: -l:libargon2.so.1
#include <stdint.h>
#include <stddef.h>
extern int argon2id_hash_raw(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
 const void *pwd, size_t pwdlen, const void *salt, size_t saltlen, void *hash, size_t hashlen);
*/
import "C"
import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

const (
	argonTime    = 3
	argonMemory  = 65536
	argonThreads = 1
	argonSaltLen = 16
	argonHashLen = 32
)

func argon(password string, salt []byte) ([]byte, error) {
	if len(password) > 4096 {
		return nil, errors.New("password too long")
	}
	out := make([]byte, argonHashLen)
	b := []byte(password)
	if int(C.argon2id_hash_raw(argonTime, argonMemory, argonThreads, unsafe.Pointer(unsafe.SliceData(b)), C.size_t(len(b)), unsafe.Pointer(unsafe.SliceData(salt)), C.size_t(len(salt)), unsafe.Pointer(unsafe.SliceData(out)), argonHashLen)) != 0 {
		return nil, errors.New("argon2id failed")
	}
	return out, nil
}
func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", errors.New("password length must be 12..256")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := argon(password, salt)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
func VerifyPassword(encoded, password string) bool {
	p := strings.Split(encoded, "$")
	if len(p) != 6 || p[1] != "argon2id" || p[2] != "v=19" || p[3] != "m=65536,t=3,p=1" {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(p[4])
	expected, e2 := base64.RawStdEncoding.DecodeString(p[5])
	if e1 != nil || e2 != nil || len(salt) != argonSaltLen || len(expected) != argonHashLen {
		return false
	}
	got, err := argon(password, salt)
	return err == nil && subtle.ConstantTimeCompare(got, expected) == 1
}
