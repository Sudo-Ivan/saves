// SPDX-License-Identifier: 0BSD

// Package vault implements client-side end-to-end encryption for saves.
// One 32-byte vault key derives subkeys via HKDF-SHA256. Chunk ciphertexts
// are deterministic so identical plaintext chunks deduplicate.
package vault

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Key is the root vault key.
type Key [32]byte

// NewKey generates a key from crypto/rand.
func NewKey() (Key, error) {
	var k Key
	_, err := rand.Read(k[:])
	return k, err
}

// ChunkOverhead is nonce+tag added to each sealed chunk.
const ChunkOverhead = 40

var (
	ErrBadPassphrase = errors.New("vault: bad passphrase")
	ErrBadHeader     = errors.New("vault: malformed header")
	ErrBadRecovery   = errors.New("vault: bad recovery key")
	ErrBadInput      = errors.New("vault: bad input")
)

// Vault holds derived subkeys; it never exposes them.
type Vault struct {
	kEnc  cipher.AEAD
	kSIV  []byte
	kPath []byte
	kMeta cipher.AEAD
	kKID  []byte
	key   Key
}

// New builds a Vault from a raw key.
func New(k Key) *Vault {
	sub := func(info string) []byte {
		b, err := hkdf.Key(sha256.New, k[:], []byte("saves-vault"), info, 32)
		if err != nil {
			panic(err)
		}
		return b
	}
	enc, _ := chacha20poly1305.NewX(sub("saves/v1/enc"))
	meta, _ := chacha20poly1305.NewX(sub("saves/v1/meta"))
	return &Vault{
		kEnc: enc, kSIV: sub("saves/v1/siv"), kPath: sub("saves/v1/path"),
		kMeta: meta, kKID: sub("saves/v1/kid"), key: k,
	}
}

// Wipe zeroes the vault key material best effort.
func (v *Vault) Wipe() {
	for i := range v.key {
		v.key[i] = 0
	}
	for i := range v.kSIV {
		v.kSIV[i] = 0
	}
	for i := range v.kPath {
		v.kPath[i] = 0
	}
	for i := range v.kKID {
		v.kKID[i] = 0
	}
}

// RootKey returns the raw vault key for keystore storage.
func (v *Vault) RootKey() Key { return v.key }

// KID returns the opaque key identifier.
func (v *Vault) KID() string {
	m := hmac.New(sha256.New, v.kKID)
	m.Write([]byte("kid"))
	return hex.EncodeToString(m.Sum(nil)[:8])
}

// PathID returns the opaque 32-char id of a path.
func (v *Vault) PathID(path string) string {
	m := hmac.New(sha256.New, v.kPath)
	m.Write([]byte(path))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

var aadChunk = []byte("saves-chunk-v1")
var aadMeta = []byte("saves-meta-v1")

// SealChunk seals plaintext deterministically (SIV-style nonce).
func (v *Vault) SealChunk(plain []byte) []byte {
	m := hmac.New(sha256.New, v.kSIV)
	m.Write(plain)
	nonce := m.Sum(nil)[:24]
	out := make([]byte, 0, len(plain)+ChunkOverhead)
	out = append(out, nonce...)
	return v.kEnc.Seal(out, nonce, plain, aadChunk)
}

// SealChunkTo appends the sealed chunk to dst.
func (v *Vault) SealChunkTo(dst, plain []byte) []byte {
	m := hmac.New(sha256.New, v.kSIV)
	m.Write(plain)
	nonce := m.Sum(nil)[:24]
	out := append(dst, nonce...)
	return v.kEnc.Seal(out, nonce, plain, aadChunk)
}

// OpenChunk opens a sealed chunk, verifying tag and nonce.
func (v *Vault) OpenChunk(ct []byte) ([]byte, error) {
	if len(ct) < 24+chacha20poly1305.Overhead {
		return nil, ErrBadInput
	}
	plain, err := v.kEnc.Open(nil, ct[:24], ct[24:], aadChunk)
	if err != nil {
		return nil, ErrBadInput
	}
	m := hmac.New(sha256.New, v.kSIV)
	m.Write(plain)
	if !hmac.Equal(m.Sum(nil)[:24], ct[:24]) {
		return nil, ErrBadInput
	}
	return plain, nil
}

// SealMeta seals metadata with a random nonce.
func (v *Vault) SealMeta(plain []byte) []byte {
	var nonce [24]byte
	_, _ = rand.Read(nonce[:])
	out := append([]byte(nil), nonce[:]...)
	return v.kMeta.Seal(out, nonce[:], plain, aadMeta)
}

// OpenMeta opens metadata.
func (v *Vault) OpenMeta(ct []byte) ([]byte, error) {
	if len(ct) < 24+chacha20poly1305.Overhead {
		return nil, ErrBadInput
	}
	return v.kMeta.Open(nil, ct[:24], ct[24:], aadMeta)
}

// SealInline seals small inline file bytes deterministically.
func (v *Vault) SealInline(plain []byte) []byte { return v.SealChunk(plain) }

// OpenInline opens sealed inline bytes.
func (v *Vault) OpenInline(ct []byte) ([]byte, error) { return v.OpenChunk(ct) }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// renderRecovery formats 32 key bytes + 2 checksum bytes for display.
func renderRecovery(key []byte) string {
	sum := sha256.Sum256(key)
	raw := append(append([]byte(nil), key...), sum[:2]...)
	s := b32.EncodeToString(raw)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// parseRecovery accepts the grouped, spaced, or mixed case form.
func parseRecovery(s string) ([]byte, error) {
	var clean []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '-' || c == '\t' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		clean = append(clean, c)
	}
	raw, err := b32.DecodeString(string(clean))
	if err != nil || len(raw) != 34 {
		return nil, ErrBadRecovery
	}
	sum := sha256.Sum256(raw[:32])
	if !hmac.Equal(sum[:2], raw[32:]) {
		return nil, ErrBadRecovery
	}
	return raw[:32], nil
}

// Header is the JSON blob stored server side.
type Header struct {
	V            int    `json:"v"`
	KID          string `json:"kid"`
	Alg          string `json:"alg"`
	Salt         string `json:"salt"`
	T            uint32 `json:"t"`
	MKiB         uint32 `json:"m_kib"`
	P            uint8  `json:"p"`
	PassWrap     string `json:"pass_wrap"`
	RecoveryWrap string `json:"recovery_wrap"`
	CreatedNS    int64  `json:"created"`
}

// KDFParams bounds argon2id work.
type KDFParams struct {
	T, MKiB uint32
	P       uint8
}

// DefaultKDF is interactive strength.
var DefaultKDF = KDFParams{T: 3, MKiB: 64 << 10, P: 4}

// LightKDF is for tests.
var LightKDF = KDFParams{T: 1, MKiB: 8 << 10, P: 1}

const maxHeaderBytes = 8 << 10

func checkKDF(p KDFParams, saltLen int) error {
	if p.T < 1 || p.T > 10 || p.MKiB < 8<<10 || p.MKiB > 1<<20 ||
		p.P < 1 || p.P > 16 || saltLen < 16 || saltLen > 64 {
		return ErrBadHeader
	}
	return nil
}
