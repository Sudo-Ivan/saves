// SPDX-License-Identifier: 0BSD

package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

var errSelfOrLastAdmin = errors.New("cannot moderate yourself or the last admin")

// Moderation holds moderation helpers on Server.
// Ban sets user_status banned and disables the user.
func (s *Server) Ban(ctx context.Context, actor, userID, reason string, until *time.Time, revokeTokens bool) error {
	if userID == actor {
		return errSelfOrLastAdmin
	}
	if isLastWebAdmin(ctx, s.Meta, userID) {
		return errSelfOrLastAdmin
	}
	if err := s.Meta.SetUserStatus(ctx, meta.UserStatus{UserID: userID,
		State: "banned", Reason: reason, At: s.now(), By: actor, Until: until}); err != nil {
		return err
	}
	s.audit(ctx, actor, actBan, "user", userID, fmt.Sprintf(`{"reason":%q}`, reason))
	s.revokeWebSessions(ctx, userID)
	if revokeTokens && s.Svc.TokenInvalidator != nil {
		s.Svc.TokenInvalidator(userID)
	}
	return nil
}

// Unban clears the status and re-enables the user.
func (s *Server) Unban(ctx context.Context, actor, userID string) error {
	if err := s.Meta.ClearUserStatus(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, actor, actUnban, "user", userID, "")
	return nil
}

// Approve clears a pending status.
func (s *Server) Approve(ctx context.Context, actor, userID string) error {
	st, err := s.Meta.GetUserStatus(ctx, userID)
	if err != nil || st.State != "pending" {
		return meta.ErrNotFound
	}
	if err := s.Meta.ClearUserStatus(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, actor, actApprove, "user", userID, "")
	return nil
}

// Reject deletes a pending user.
func (s *Server) Reject(ctx context.Context, actor, userID string) error {
	st, err := s.Meta.GetUserStatus(ctx, userID)
	if err != nil || st.State != "pending" {
		return meta.ErrNotFound
	}
	if userID == actor || isLastWebAdmin(ctx, s.Meta, userID) {
		return errSelfOrLastAdmin
	}
	if err := s.Meta.DeleteUser(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, actor, actReject, "user", userID, "")
	return nil
}

// AdminSetPassword sets or generates a password and forces change.
func (s *Server) AdminSetPassword(ctx context.Context, actor, userID, pw string, generate bool) (string, error) {
	if generate {
		pw = randPassword(20)
	} else if err := auth.CheckPasswordPolicy(pw, ""); err != nil {
		return "", err
	}
	ph, err := auth.HashPassword(pw)
	if err != nil {
		return "", err
	}
	if err := s.Meta.UpdateCredential(ctx, userID, meta.CredentialPatch{
		PasswordHash: &ph, MustChange: &tru}); err != nil {
		return "", err
	}
	s.revokeWebSessions(ctx, userID)
	s.audit(ctx, actor, actSetPassword, "user", userID, "")
	return pw, nil
}

var tru = true

func randPassword(n int) string {
	const az = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = az[int(b[i])%len(az)]
	}
	return string(b)
}

func isLastWebAdmin(ctx context.Context, m meta.Store, userID string) bool {
	rows, _, err := m.ListUsersAdmin(ctx, meta.UserFilter{AdminOnly: true}, 0, 100)
	if err != nil {
		return false
	}
	n := 0
	for _, r := range rows {
		if r.User.ID == userID {
			continue
		}
		n++
	}
	// userID is an admin and the only one left
	for _, r := range rows {
		if r.User.ID == userID && n == 0 {
			return true
		}
	}
	return false
}

func (s *Server) revokeWebSessions(ctx context.Context, userID string) {
	if d, ok := s.Meta.(interface {
		RevokeAllWebSessions(ctx context.Context, userID string) error
	}); ok {
		_ = d.RevokeAllWebSessions(ctx, userID)
	}
}

func (s *Server) audit(ctx context.Context, actor, action, ttype, tid, detail string) {
	if s.auditor == nil {
		return
	}
	e := meta.AuditEvent{ActorID: actor, Action: action, TargetType: ttype,
		TargetID: tid, Detail: detail, At: s.now()}
	id, _ := meta.NewID(e.At)
	e.ID = id
	s.auditor.Record(ctx, e)
}

func (s *Server) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// ipBlocks caches the active block list for the middleware.
type ipBlocks struct {
	mu     sync.RWMutex
	list   []netip.Prefix
	fresh  time.Time
	denied map[string]time.Time
	self   netip.Prefix
}

// AddIPBlock adds a block; self and trusted proxies are refused.
func (s *Server) AddIPBlock(ctx context.Context, actor, cidr, reason string, expires *time.Time) error {
	p, err := parseBlockCIDR(cidr)
	if err != nil {
		return err
	}

	for _, tp := range s.Cfg.TrustedProxyPrefixes() {
		if p.Overlaps(tp) {
			return errors.New("block overlaps a trusted proxy")
		}
	}
	if ip, ok := ctx.Value(clientIPKey{}).(netip.Addr); ok {
		if p.Contains(ip) {
			return errors.New("block covers your own address")
		}
	}
	id, _ := meta.NewID(s.now())
	return s.Meta.AddIPBlock(ctx, meta.IPBlock{ID: id, CIDR: p.String(),
		Reason: reason, CreatedBy: actor, CreatedAt: s.now(), ExpiresAt: expires})
}

// RemoveIPBlock deletes one row.
func (s *Server) RemoveIPBlock(ctx context.Context, id string) error {
	return s.Meta.DeleteIPBlock(ctx, id)
}

type clientIPKey struct{}

// ctxWithIP attaches the acting admin's address for self-overlap checks.
func ctxWithIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

func parseBlockCIDR(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ipBlockMW rejects blocked client IPs at the front of the chain.
func (s *Server) ipBlockMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.blocks == nil {
			next.ServeHTTP(w, r)
			return
		}
		ip := netx.ClientIPReal(r, s.trustedCIDRs(), s.Cfg.Proxy.RealIPHeader)
		if s.blocked(r.Context(), ip) {
			s.blocks.mu.Lock()
			last, seen := s.blocks.denied[ip.String()]
			if !seen || s.now().Sub(last) > 10*time.Minute {
				s.blocks.denied[ip.String()] = s.now()
				s.blocks.mu.Unlock()
				s.audit(r.Context(), "", actIPBlock, "ip", ip.String(), "")
			} else {
				s.blocks.mu.Unlock()
			}
			if strings.HasPrefix(r.URL.Path, "/v1/") {
				s.writeProblem(w, r, &api.Problem{Code: api.CodeIPBlocked,
					Title: "address blocked", Status: 403})
				return
			}
			wv := &webReq{s: s, w: w, r: r, web: s.web}
			wv.errorPage(403)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) blocked(ctx context.Context, ip netip.Addr) bool {
	s.blocks.mu.RLock()
	fresh := s.now().Sub(s.blocks.fresh) < 10*time.Second
	list := s.blocks.list
	s.blocks.mu.RUnlock()
	if !fresh {
		rows, err := s.Meta.ListIPBlocks(ctx)
		if err == nil {
			now := s.now()
			list = nil
			for _, b := range rows {
				if b.ExpiresAt != nil && b.ExpiresAt.Before(now) {
					continue
				}
				if p, err := netip.ParsePrefix(b.CIDR); err == nil {
					list = append(list, p)
				}
			}
			s.blocks.mu.Lock()
			s.blocks.list = list
			s.blocks.fresh = now
			s.blocks.mu.Unlock()
		}
	}
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
