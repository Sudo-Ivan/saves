// SPDX-License-Identifier: 0BSD

// Package api defines the saves wire types: hashes, manifests, limits,
// path rules, strict decoding, and RFC 9457 problem responses.
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Hash is a SHA-256 digest, serialized as 64 lowercase hex characters.
type Hash [32]byte

// HashBytes returns the SHA-256 of b.
func HashBytes(b []byte) Hash {
	return Hash(sha256.Sum256(b))
}

// ParseHash parses a 64 character lowercase hex string.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 64 {
		return h, fmt.Errorf("hash: want 64 hex chars, got %d", len(s))
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, fmt.Errorf("hash: %w", err)
	}
	return h, nil
}

// String returns the lowercase hex encoding.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// IsZero reports whether h is all zeroes.
func (h Hash) IsZero() bool {
	return h == Hash{}
}

// MarshalJSON encodes as 64 lowercase hex characters.
func (h Hash) MarshalJSON() ([]byte, error) {
	var b [66]byte
	b[0] = '"'
	hex.Encode(b[1:65], h[:])
	b[65] = '"'
	return b[:], nil
}

// UnmarshalJSON decodes a 64 character lowercase hex string.
func (h *Hash) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if len(s) != 64 {
		return errors.New("hash: want 64 hex chars")
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return fmt.Errorf("hash: %w", err)
	}
	return nil
}
