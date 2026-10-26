// SPDX-License-Identifier: 0BSD

package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundtrip(t *testing.T) {
	ph, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ph, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("bad phc: %s", ph)
	}
	ok, rehash, err := VerifyPassword(ph, "correct horse battery")
	if err != nil || !ok || rehash {
		t.Fatalf("verify: %v ok=%v rehash=%v", err, ok, rehash)
	}
	ok, _, err = VerifyPassword(ph, "wrong horse")
	if err != nil || ok {
		t.Fatal("wrong password verified")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("short", "") == nil {
		t.Fatal("short accepted")
	}
	if CheckPasswordPolicy(strings.Repeat("a", 300), "") == nil {
		t.Fatal("too long accepted")
	}
	if CheckPasswordPolicy("usernameuser", "UsernameUser") == nil {
		t.Fatal("password equal to username accepted")
	}
	if CheckPasswordPolicy("a very fine passphrase", "u") != nil {
		t.Fatal("good password rejected")
	}
}

// RFC 6238 appendix B test vectors use a 20 byte ASCII secret for SHA1
// at 59s (T=1), which yields 94287082 for 8 digits, 287082 for 6.
func TestTOTPVector(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(59, 0)
	if got := TOTPCode(secret, at); got != "287082" {
		t.Fatalf("got %s", got)
	}
	step, ok := VerifyTOTP(secret, "287082", at)
	if !ok || step != 1 {
		t.Fatalf("verify: %v %d", ok, step)
	}
	// Window: same code one step off must not verify.
	if _, ok := VerifyTOTP(secret, "287082", at.Add(90*time.Second)); ok {
		t.Fatal("stale code accepted")
	}
	// Neighbor step code verifies within the window.
	code := TOTPCode(secret, at.Add(30*time.Second))
	if _, ok := VerifyTOTP(secret, code, at); !ok {
		t.Fatal("window step rejected")
	}
	if _, ok := VerifyTOTP(secret, "00000x", at); ok {
		t.Fatal("non digit accepted")
	}
}

func TestTOTPURIAndSecret(t *testing.T) {
	sec, err := NewTOTPSecret()
	if err != nil || len(sec) != TOTPSecretLen {
		t.Fatal("secret")
	}
	u := TOTPURI("saves", "alice", sec)
	if !strings.HasPrefix(u, "otpauth://totp/saves:alice?") || !strings.Contains(u, "issuer=saves") {
		t.Fatalf("uri %s", u)
	}
	b, err := ParseTOTPSecret(strings.ToLower(TOTPSecretBase32(sec)))
	if err != nil || string(b) != string(sec) {
		t.Fatal("base32 roundtrip")
	}
}

func TestSecretbox(t *testing.T) {
	master := []byte("master-secret-master-secret-1234")
	ct, err := Seal(master, SealTOTPSecret, []byte("u1"), []byte("top secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(master, SealTOTPSecret, []byte("u1"), ct)
	if err != nil || string(pt) != "top secret" {
		t.Fatal("roundtrip")
	}
	// Wrong purpose or ad fails.
	if _, err := Open(master, SealCSRFHMAC, []byte("u1"), ct); err != ErrSeal {
		t.Fatal("wrong purpose opened")
	}
	if _, err := Open(master, SealTOTPSecret, []byte("u2"), ct); err != ErrSeal {
		t.Fatal("wrong ad opened")
	}
	// Tamper fails.
	ct[0] ^= 1
	if _, err := Open(master, SealTOTPSecret, []byte("u1"), ct); err != ErrSeal {
		t.Fatal("tampered opened")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil || len(codes) != RecoveryCount {
		t.Fatal("count")
	}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("bad code %q", c)
		}
		h := HashRecovery("  " + strings.ToUpper(c) + " ")
		h2 := HashRecovery(c)
		if h != h2 {
			t.Fatal("normalization")
		}
	}
}
