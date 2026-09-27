// Package passwordhash implements FR-PWD-004's password hashing (Argon2id,
// with a bcrypt verify path for legacy credentials, FR-LOGIN-005) plus the
// timing-consistency helper FR-LOGIN-002/003/007 require. It is a shared
// platform package, not nested in the login feature, because password
// change/reset will reuse Hash/Verify unchanged.
package passwordhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2idParams are the cost parameters (FR-PWD-004: t=3, m=65536, p=4).
type Argon2idParams struct {
	TimeCost    uint32
	MemoryKB    uint32
	Parallelism uint8
}

const (
	saltLen = 16
	keyLen  = 32
)

// Hash derives an Argon2id hash of plaintext with a fresh random salt.
// Both hash and salt are returned as standard base64 (RawStdEncoding),
// matching the credentials table's password_hash/password_salt columns.
func Hash(plaintext string, p Argon2idParams) (hash, salt string, err error) {
	saltBytes := make([]byte, saltLen)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", "", fmt.Errorf("passwordhash: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(plaintext), saltBytes, p.TimeCost, p.MemoryKB, p.Parallelism, keyLen)
	return base64.RawStdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(saltBytes), nil
}

// Verify reports whether plaintext produces hash under salt/p, using a
// constant-time comparison of the derived keys.
func Verify(plaintext, hash, salt string, p Argon2idParams) bool {
	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(plaintext), saltBytes, p.TimeCost, p.MemoryKB, p.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// VerifyBcrypt verifies plaintext against a legacy bcrypt hash (FR-LOGIN-005,
// migration-only path). bcrypt.CompareHashAndPassword is already
// constant-time.
func VerifyBcrypt(plaintext, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// dummySalt is a fixed, non-secret salt used only to burn CPU time; it never
// gates access and is never compared against anything, so it does not need
// to be a real secret.
var dummySalt = []byte("araquanid-dummy-argon2id-salt-16")

// DummyVerify computes an Argon2id hash against a fixed salt and discards the
// result, burning the same CPU cost as a real Verify call. Used when an
// identity/credential is not found so the response time is indistinguishable
// from a real wrong-password check (FR-LOGIN-002, FR-LOGIN-003, FR-LOGIN-007).
func DummyVerify(plaintext string, p Argon2idParams) {
	_ = argon2.IDKey([]byte(plaintext), dummySalt[:saltLen], p.TimeCost, p.MemoryKB, p.Parallelism, keyLen)
}
