// SPDX-License-Identifier: 0BSD

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Purpose labels for key derivation. Each purpose gets an independent
// key from the shared web secret via HKDF-SHA256.
const (
	SealTOTPSecret = "totp-seal"
	SealCSRFHMAC   = "csrf-hmac"
	SealOIDCCookie = "oidc-cookie-seal"
)

// ErrSeal is a generic unseal failure; details are not distinguished.
var ErrSeal = errors.New("auth: sealed value invalid")

// DeriveKey returns the 32 byte key for a purpose label.
func DeriveKey(secret []byte, purpose string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("auth: empty master secret")
	}
	k := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(purpose)), k); err != nil {
		return nil, err
	}
	return k, nil
}

// Seal encrypts pt with AES-256-GCM under the purpose key, binding ad.
func Seal(secret []byte, purpose string, ad, pt []byte) ([]byte, error) {
	k, err := DeriveKey(secret, purpose)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, pt, ad), nil
}

// Open reverses Seal.
func Open(secret []byte, purpose string, ad, ct []byte) ([]byte, error) {
	k, err := DeriveKey(secret, purpose)
	if err != nil {
		return nil, err
	}
	gcm, err := gcmFor(k)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrSeal
	}
	pt, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], ad)
	if err != nil {
		return nil, ErrSeal
	}
	return pt, nil
}

func gcmFor(k []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// SealString is the string form of Seal with base64url output.
func SealString(secret []byte, purpose, ad, pt string) (string, error) {
	ct, err := Seal(secret, purpose, []byte(ad), []byte(pt))
	if err != nil {
		return "", err
	}
	return b64url(ct), nil
}

// OpenString reverses SealString.
func OpenString(secret []byte, purpose, ad, s string) (string, error) {
	ct, err := b64urlDec(s)
	if err != nil {
		return "", ErrSeal
	}
	pt, err := Open(secret, purpose, []byte(ad), ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// HMACKey returns the derived csrf-hmac key for token signing.
func HMACKey(secret []byte) ([]byte, error) {
	return DeriveKey(secret, SealCSRFHMAC)
}

// HMAC computes HMAC-SHA256 under an already derived key.
func HMAC(key, msg []byte) [32]byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64urlDec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
