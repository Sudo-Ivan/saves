// SPDX-License-Identifier: 0BSD

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
)

// Recovery codes are 10 characters from an unambiguous base32 alphabet
// displayed as xxxxx-xxxxx and stored as SHA-256 only.
const (
	RecoveryCount = 10
	recoveryLen   = 10
	// No 0, 1, i, l, o, u: no lookalikes, no vowels.
	recoveryAlphabet = "abcdefghjkmnpqrstvwxyz23456789"
)

// GenerateRecoveryCodes returns the display codes (xxxxx-xxxxx).
func GenerateRecoveryCodes() ([]string, error) {
	out := make([]string, 0, RecoveryCount)
	for len(out) < RecoveryCount {
		var b [recoveryLen]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		var code strings.Builder
		for i, c := range b {
			if i == 5 {
				code.WriteByte('-')
			}
			code.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		out = append(out, code.String())
	}
	return out, nil
}

// NormalizeRecovery strips separators and case for lookup.
func NormalizeRecovery(code string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// HashRecovery returns the stored digest of a normalized code.
func HashRecovery(code string) [32]byte {
	return sha256.Sum256([]byte(NormalizeRecovery(code)))
}
