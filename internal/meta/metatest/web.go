// SPDX-License-Identifier: 0BSD

package metatest

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/meta/testclock"
)

// testWeb exercises credentials, recovery codes, and web sessions.
func testWeb(t *testing.T, f Factory) {
	s := f(t, testclock.New(time.Now()))
	ctx := context.Background()
	u := mkUser(t, s, "web-user")

	// Credential create/get.
	c := meta.WebCredential{UserID: u.ID, Username: "Alice", PasswordHash: "$argon2id$x"} // #nosec G101 -- column list or usage text, not a credential
	if err := s.CreateCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCredentialByUsername(ctx, "ALICE")
	if err != nil || got.Username != "alice" {
		t.Fatalf("username lookup: %v %q", err, got.Username)
	}
	got, err = s.GetCredential(ctx, u.ID)
	if err != nil || got.UserID != u.ID {
		t.Fatalf("credential by user: %v", err)
	}
	if _, err := s.GetCredentialByUsername(ctx, "nobody"); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("expected ErrNotFound")
	}
	// Username clash yields ErrExists.
	c2 := c
	c2.UserID = mkUser(t, s, "web-user-2").ID
	if err := s.CreateCredential(ctx, c2); !errors.Is(err, meta.ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}

	// Patch.
	if err := s.UpdateCredential(ctx, u.ID, meta.CredentialPatch{
		PasswordHash: strp("$argon2id$y"), MustChange: boolp(true), Admin: boolp(true),
		TOTPEnabled: boolp(true), TOTPSecret: bytesp([]byte("sealed")),
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetCredential(ctx, u.ID)
	if !got.MustChange || !got.Admin || !got.TOTPEnabled || string(got.TOTPSecret) != "sealed" || got.PasswordHash != "$argon2id$y" {
		t.Fatalf("patch not applied: %+v", got)
	}
	// Clear TOTP.
	empty := []byte{}
	if err := s.UpdateCredential(ctx, u.ID, meta.CredentialPatch{TOTPSecret: &empty, TOTPEnabled: boolp(false)}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetCredential(ctx, u.ID)
	if got.TOTPSecret != nil || got.TOTPEnabled {
		t.Fatal("totp not cleared")
	}

	// Recovery codes: set, consume once, reject reuse, replace.
	h1 := sha256.Sum256([]byte("code1"))
	h2 := sha256.Sum256([]byte("code2"))
	if err := s.SetRecoveryCodes(ctx, u.ID, [][32]byte{h1, h2}); err != nil {
		t.Fatal(err)
	}
	rem, err := s.ConsumeRecoveryCode(ctx, u.ID, h1)
	if err != nil || rem != 1 {
		t.Fatalf("consume: %v rem=%d", err, rem)
	}
	if _, err := s.ConsumeRecoveryCode(ctx, u.ID, h1); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("reuse must fail")
	}
	h3 := sha256.Sum256([]byte("code3"))
	if err := s.SetRecoveryCodes(ctx, u.ID, [][32]byte{h3}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRecoveryCode(ctx, u.ID, h2); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("old set must be invalid after regeneration")
	}

	// TOTP step compare and set.
	ok, err := s.AdvanceTOTPStep(ctx, u.ID, 100)
	if err != nil || !ok {
		t.Fatal("first advance must succeed")
	}
	ok, err = s.AdvanceTOTPStep(ctx, u.ID, 100)
	if err != nil || ok {
		t.Fatal("replay step must fail")
	}
	ok, err = s.AdvanceTOTPStep(ctx, u.ID, 99)
	if err != nil || ok {
		t.Fatal("older step must fail")
	}
	ok, err = s.AdvanceTOTPStep(ctx, u.ID, 101)
	if err != nil || !ok {
		t.Fatal("newer step must succeed")
	}

	// Sessions.
	var idh1, idh2, idh3 [32]byte
	idh1[0], idh2[0], idh3[0] = 1, 2, 3
	now := time.Now()
	mkSess := func(h [32]byte, kind string) meta.WebSession {
		var csrf [32]byte
		csrf[0] = 9
		return meta.WebSession{IDHash: h, UserID: u.ID, Kind: kind, Method: "password",
			CSRF: csrf, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
			IP: "1.2.3.4/32", UserAgent: "ua"}
	}
	for _, w := range []meta.WebSession{mkSess(idh1, meta.SessionFull), mkSess(idh2, meta.SessionFull), mkSess(idh3, meta.SessionPending)} {
		if err := s.CreateWebSession(ctx, w); err != nil {
			t.Fatal(err)
		}
	}
	ws, err := s.GetWebSession(ctx, idh1)
	if err != nil || ws.UserID != u.ID || ws.Kind != meta.SessionFull || ws.CSRF[0] != 9 {
		t.Fatalf("get session: %v %+v", err, ws)
	}
	list, err := s.ListWebSessions(ctx, u.ID)
	if err != nil || len(list) != 3 {
		t.Fatalf("list sessions: %v %d", err, len(list))
	}
	if err := s.TouchWebSession(ctx, idh1, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err := s.BumpWebSessionAttempts(ctx, idh3)
	if err != nil || n != 1 {
		t.Fatalf("bump: %v %d", err, n)
	}
	// Delete all except one.
	del, err := s.DeleteUserSessions(ctx, u.ID, &idh2)
	if err != nil || del != 2 {
		t.Fatalf("delete user sessions: %v %d", err, del)
	}
	list, _ = s.ListWebSessions(ctx, u.ID)
	if len(list) != 1 || list[0].IDHash != idh2 {
		t.Fatalf("expected only idh2 left, got %+v", list)
	}
	if err := s.DeleteWebSession(ctx, idh2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWebSession(ctx, idh2); !errors.Is(err, meta.ErrNotFound) {
		t.Fatal("expected ErrNotFound")
	}

	// Purge expired.
	if err := s.CreateWebSession(ctx, meta.WebSession{
		IDHash: idh1, UserID: u.ID, Kind: meta.SessionFull, Method: "password",
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	purged, err := s.PurgeWebSessions(ctx, now)
	if err != nil || purged != 1 {
		t.Fatalf("purge: %v %d", err, purged)
	}
}

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }
func bytesp(b []byte) *[]byte {
	return &b
}
