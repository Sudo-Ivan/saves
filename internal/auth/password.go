// SPDX-License-Identifier: 0BSD

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password policy and argon2id parameters. The stored PHC string
// carries the parameters used so old hashes keep verifying and can be
// rehashed on a successful login.
const (
	PasswordMinChars = 12
	PasswordMaxBytes = 256

	argonMemKiB  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	// ErrPasswordPolicy fires when a password fails the policy checks.
	ErrPasswordPolicy = errors.New("auth: password does not meet policy")
	// ErrHashBusy fires when the argon2 worker pool is saturated; map
	// to HTTP 503 with Retry-After.
	ErrHashBusy = errors.New("auth: password hashing busy")
)

// hashSem bounds concurrent argon2 runs; each costs 64 MiB of RAM.
var hashSem = make(chan struct{}, 4)

func acquireHash() error {
	select {
	case hashSem <- struct{}{}:
		return nil
	default:
		return ErrHashBusy
	}
}

// CheckPasswordPolicy enforces the password rules. Username may be
// empty for callers that do not have it.
func CheckPasswordPolicy(password, username string) error {
	if len(password) < PasswordMinChars || len(password) > PasswordMaxBytes {
		return ErrPasswordPolicy
	}
	if username != "" && strings.EqualFold(password, username) {
		return ErrPasswordPolicy
	}
	return nil
}

// HashPassword returns a PHC format argon2id string.
func HashPassword(password string) (string, error) {
	if err := acquireHash(); err != nil {
		return "", err
	}
	defer func() { <-hashSem }()
	var salt [argonSaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt[:], argonTime, argonMemKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt[:]),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// parsePHC decodes an argon2id PHC string.
func parsePHC(phc string) (salt, key []byte, mem uint32, t uint32, p uint8, err error) {
	parts := strings.Split(phc, "$")
	// $argon2id$v=19$m=...,t=...,p=...$salt$key
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, nil, 0, 0, 0, errors.New("auth: bad password hash")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return nil, nil, 0, 0, 0, errors.New("auth: bad password hash params")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return nil, nil, 0, 0, 0, errors.New("auth: bad password hash salt")
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 || len(key) > 64 || len(salt) > 64 {
		return nil, nil, 0, 0, 0, errors.New("auth: bad password hash key")
	}
	if mem < 8 || mem > 256<<10 || t < 1 || t > 10 || p < 1 || p > 16 {
		return nil, nil, 0, 0, 0, errors.New("auth: password hash parameters out of range")
	}
	return salt, key, mem, t, p, nil
}

// VerifyPassword checks password against a PHC string. It reports
// whether the stored hash should be rehashed with current parameters.
func VerifyPassword(phc, password string) (ok, rehash bool, err error) {
	salt, key, mem, t, p, err := parsePHC(phc)
	if err != nil {
		return false, false, err
	}
	if err := acquireHash(); err != nil {
		return false, false, err
	}
	defer func() { <-hashSem }()
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(key))) // #nosec G115 -- parsePHC bounds the key length
	ok = subtle.ConstantTimeCompare(got, key) == 1
	rehash = ok && (mem != argonMemKiB || t != argonTime || p != argonThreads || len(key) != argonKeyLen)
	return ok, rehash, nil
}

// dummyPHC is a valid argon2id hash used to spend equal time when the
// username is unknown so login failures are indistinguishable.
const dummyPHC = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// VerifyDummy spends the same work as VerifyPassword on the dummy hash.
func VerifyDummy(password string) {
	_, _, _ = VerifyPassword(dummyPHC, password)
}
