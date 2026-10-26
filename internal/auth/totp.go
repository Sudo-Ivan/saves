// SPDX-License-Identifier: 0BSD

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 mandates SHA-1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters, fixed to the widely supported profile.
const (
	TOTPSecretLen = 20
	totpDigits    = 6
	totpPeriod    = 30
)

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh 20 byte secret.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, TOTPSecretLen)
	_, err := rand.Read(b)
	return b, err
}

// TOTPSecretBase32 encodes a secret for display and otpauth URIs.
func TOTPSecretBase32(secret []byte) string {
	return totpB32.EncodeToString(secret)
}

// ParseTOTPSecret decodes a base32 secret, tolerating lowercase and
// spaces.
func ParseTOTPSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	return totpB32.DecodeString(s)
}

// hotp computes the counter based one time code per RFC 4226.
func hotp(secret []byte, counter uint64) uint32 {
	mac := hmac.New(sha1.New, secret)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	mac.Write(c[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return bin % 1000000
}

// TOTPCode returns the 6 digit code for secret at the given time.
func TOTPCode(secret []byte, at time.Time) string {
	c := hotp(secret, uint64(at.Unix())/totpPeriod) // #nosec G115 -- unix time is positive
	const digits = "0123456789"
	var out [totpDigits]byte
	for i := totpDigits - 1; i >= 0; i-- {
		out[i] = digits[c%10]
		c /= 10
	}
	return string(out[:])
}

// VerifyTOTP checks a user supplied code within a +-1 step window. It
// returns the matching step counter, which the caller must persist to
// prevent replay, and whether the code matched at all. The comparison
// is constant time over all candidate steps.
func VerifyTOTP(secret []byte, code string, at time.Time) (step int64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	var want uint32
	for _, ch := range []byte(code) {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		want = want*10 + uint32(ch-'0')
	}
	var want4 [4]byte
	binary.BigEndian.PutUint32(want4[:], want)
	if at.Unix() < totpPeriod {
		return 0, false
	}
	base := uint64(at.Unix()) / totpPeriod // #nosec G115 -- checked positive above
	for d := int64(-1); d <= 1; d++ {
		cand := base + uint64(d) // #nosec G115 -- d is -1, 0 or 1 and base is at least 1
		var got4 [4]byte
		binary.BigEndian.PutUint32(got4[:], hotp(secret, cand))
		if subtle.ConstantTimeCompare(got4[:], want4[:]) == 1 {
			return int64(cand), true // #nosec G115 -- a step count fits int64
		}
	}
	return 0, false
}

// TOTPURI builds an otpauth:// provisioning URI.
func TOTPURI(issuer, account string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", TOTPSecretBase32(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + v.Encode()
}
