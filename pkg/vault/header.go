// SPDX-License-Identifier: 0BSD

package vault

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var wrapAAD = []byte("saves-wrap-v1")

// wrapKey seals the vault key under a KEK.
func wrapKey(kek, kid []byte, key Key) (string, error) {
	a, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return "", err
	}
	var nonce [24]byte
	_, _ = rand.Read(nonce[:])
	out := append([]byte(nil), nonce[:]...)
	out = a.Seal(out, nonce[:], key[:], append(append([]byte(nil), wrapAAD...), kid...))
	return hex.EncodeToString(out), nil
}

func unwrapKey(kek, kid []byte, wrapHex string) (Key, error) {
	var k Key
	raw, err := hex.DecodeString(wrapHex)
	if err != nil || len(raw) < 40 {
		return k, ErrBadHeader
	}
	a, err := chacha20poly1305.NewX(kek)
	if err != nil {
		return k, err
	}
	plain, err := a.Open(nil, raw[:24], raw[24:], append(append([]byte(nil), wrapAAD...), kid...))
	if err != nil || len(plain) != 32 {
		return k, ErrBadPassphrase
	}
	copy(k[:], plain)
	return k, nil
}

func deriveKEK(pass string, salt []byte, p KDFParams) []byte {
	return argon2.IDKey([]byte(pass), salt, p.T, p.MKiB, p.P, 32)
}

func render(v *Vault) *Header {
	var h Header
	h.V = 1
	h.KID = v.KID()
	return &h
}

// Create makes a new vault for passphrase.
func Create(passphrase string, p KDFParams) (v *Vault, recovery string, header []byte, err error) {
	key, err := NewKey()
	if err != nil {
		return nil, "", nil, err
	}
	v = New(key)
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	kek := deriveKEK(passphrase, salt, p)
	h := render(v)
	h.Alg = "argon2id"
	h.Salt = hex.EncodeToString(salt)
	h.T, h.MKiB, h.P = p.T, p.MKiB, p.P
	h.PassWrap, err = wrapKey(kek, []byte(h.KID), key)
	if err != nil {
		return nil, "", nil, err
	}
	rk := make([]byte, 32)
	_, _ = rand.Read(rk)
	h.RecoveryWrap, err = wrapKey(rk, []byte(h.KID), key)
	if err != nil {
		return nil, "", nil, err
	}
	h.CreatedNS = time.Now().UnixNano()
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, "", nil, err
	}
	return v, renderRecovery(rk), hb, nil
}

func parseHeader(b []byte) (*Header, error) {
	if len(b) == 0 || len(b) > maxHeaderBytes {
		return nil, ErrBadHeader
	}
	var h Header
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, ErrBadHeader
	}
	if h.V != 1 || h.Alg != "argon2id" {
		return nil, ErrBadHeader
	}
	salt, err := hex.DecodeString(h.Salt)
	if err != nil {
		return nil, ErrBadHeader
	}
	if err := checkKDF(KDFParams{T: h.T, MKiB: h.MKiB, P: h.P}, len(salt)); err != nil {
		return nil, err
	}
	return &h, nil
}

// Unlock derives the KEK from passphrase and unwraps the vault key.
func Unlock(header []byte, passphrase string) (*Vault, error) {
	h, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	salt, _ := hex.DecodeString(h.Salt)
	kek := deriveKEK(passphrase, salt, KDFParams{T: h.T, MKiB: h.MKiB, P: h.P})
	key, err := unwrapKey(kek, []byte(h.KID), h.PassWrap)
	if err != nil {
		return nil, ErrBadPassphrase
	}
	return New(key), nil
}

// UnlockRecovery unwraps with the recovery key.
func UnlockRecovery(header []byte, recovery string) (*Vault, error) {
	h, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	rk, err := parseRecovery(recovery)
	if err != nil {
		return nil, err
	}
	key, err := unwrapKey(rk, []byte(h.KID), h.RecoveryWrap)
	if err != nil {
		return nil, ErrBadRecovery
	}
	return New(key), nil
}

// ChangePassphrase rewraps under a new passphrase.
func ChangePassphrase(header []byte, old, newPass string, p KDFParams) ([]byte, error) {
	v, err := Unlock(header, old)
	if err != nil {
		return nil, err
	}
	h, _ := parseHeader(header)
	var key Key
	copy(key[:], v.key[:])
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	kek := deriveKEK(newPass, salt, p)
	h.Salt = hex.EncodeToString(salt)
	h.T, h.MKiB, h.P = p.T, p.MKiB, p.P
	h.PassWrap, err = wrapKey(kek, []byte(h.KID), key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(h)
}

// NewRecovery issues a fresh recovery wrap.
func NewRecovery(header []byte, v *Vault) (string, []byte, error) {
	h, err := parseHeader(header)
	if err != nil {
		return "", nil, err
	}
	rk := make([]byte, 32)
	_, _ = rand.Read(rk)
	h.RecoveryWrap, err = wrapKey(rk, []byte(h.KID), v.key)
	if err != nil {
		return "", nil, err
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return "", nil, err
	}
	return renderRecovery(rk), hb, nil
}

var _ = cipher.AEAD(nil)
