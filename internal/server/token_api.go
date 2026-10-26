// SPDX-License-Identifier: 0BSD

package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// tokenView is the API shape of a token. It never carries the secret
// or its hash.
type tokenView struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Name         string     `json:"name"`
	Scopes       []string   `json:"scopes"`
	Apps         []string   `json:"apps"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
}

func viewToken(t meta.Token) tokenView {
	nz := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return tokenView{ID: t.ID, UserID: t.UserID, Name: t.Name, Scopes: nz(t.Scopes), Apps: nz(t.Apps),
		AllowedCIDRs: nz(t.AllowedCIDRs), CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt, LastUsedAt: t.LastUsedAt}
}

func viewTokens(in []meta.Token) []tokenView {
	out := make([]tokenView, len(in))
	for i, t := range in {
		out[i] = viewToken(t)
	}
	return out
}

type eventView struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	IP        string    `json:"ip,omitempty"`
	ActorID   string    `json:"actor_user_id,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

type statsView struct {
	Total        int64            `json:"total_requests"`
	Last24h      int64            `json:"requests_24h"`
	Last7d       int64            `json:"requests_7d"`
	Last30d      int64            `json:"requests_30d"`
	Daily        []int64          `json:"daily_30d"`
	UniqueIPs30d int64            `json:"unique_ips_30d"`
	TopIPs       []ipCountView    `json:"top_ips"`
	Denied       map[string]int64 `json:"denied_30d"`
	FirstUse     *time.Time       `json:"first_use"`
	LastUse      *time.Time       `json:"last_use"`
}

type ipCountView struct {
	IP        string    `json:"ip"`
	Requests  int64     `json:"requests"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent,omitempty"`
}

func viewStats(st meta.TokenStats) statsView {
	v := statsView{Total: st.Total, Last24h: st.Last24h, Last7d: st.Last7d, Last30d: st.Last30d,
		Daily: st.Daily, UniqueIPs30d: st.UniqueIPs30d, Denied: st.Denied,
		FirstUse: st.FirstUse, LastUse: st.LastUse, TopIPs: []ipCountView{}}
	if v.Daily == nil {
		v.Daily = make([]int64, 30)
	}
	if v.Denied == nil {
		v.Denied = map[string]int64{}
	}
	for _, c := range st.TopIPs {
		v.TopIPs = append(v.TopIPs, ipCountView{IP: c.IP, Requests: c.Requests, LastSeen: c.LastSeen, UserAgent: c.UserAgent})
	}
	return v
}

// expiryInput reads the expires_at and expires_in pair. set reports
// whether either was present, and a nil time with set true clears.
func expiryInput(at json.RawMessage, in string) (exp *time.Time, set bool, err error) {
	hasAt := len(at) > 0
	if hasAt && in != "" {
		return nil, false, &api.Problem{Code: api.CodeBadRequest, Title: "send expires_at or expires_in, not both", Status: 400}
	}
	if in != "" {
		d, err := service.ParseTTL(in)
		if err != nil {
			return nil, false, err
		}
		t := time.Now().Add(d)
		return &t, true, nil
	}
	if !hasAt {
		return nil, false, nil
	}
	if string(at) == "null" {
		return nil, true, nil
	}
	var str string
	if json.Unmarshal(at, &str) != nil {
		return nil, false, &api.Problem{Code: api.CodeBadRequest, Title: "invalid expires_at", Status: 400}
	}
	t, perr := time.Parse(time.RFC3339, str)
	if perr != nil {
		return nil, false, &api.Problem{Code: api.CodeBadRequest, Title: "invalid expires_at", Status: 400}
	}
	return &t, true, nil
}

func (s *Server) hTokenPatch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	var in struct {
		Name         *string         `json:"name"`
		ExpiresAt    json.RawMessage `json:"expires_at"`
		ExpiresIn    string          `json:"expires_in"`
		AllowedCIDRs *[]string       `json:"allowed_cidrs"`
	}
	if err := s.decodeJSON(w, r, &in, 1<<20); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	exp, set, err := expiryInput(in.ExpiresAt, in.ExpiresIn)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	patch := meta.TokenPatch{Name: in.Name, CIDRs: in.AllowedCIDRs}
	if set {
		patch.ExpiresAt = &exp
	}
	id := r.PathValue("id")
	if err := s.Svc.UpdateToken(r.Context(), p, id, patch); err != nil {
		s.writeProblem(w, r, err)
		return
	}
	t, err := s.Svc.GetToken(r.Context(), p, id)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, viewToken(t))
}

func (s *Server) hTokenGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	t, err := s.Svc.GetToken(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, viewToken(t))
}

func (s *Server) hTokenEvents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "limit must be 1 to 100", Status: 400})
			return
		}
		limit = n
	}
	kind := q.Get("kind")
	if kind != "" && !validEventKind(kind) {
		s.writeProblem(w, r, &api.Problem{Code: api.CodeBadRequest, Title: "unknown kind", Status: 400})
		return
	}
	ev, next, err := s.Svc.TokenEvents(r.Context(), p, r.PathValue("id"), kind, q.Get("cursor"), limit)
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	items := make([]eventView, len(ev))
	for i, e := range ev {
		items[i] = eventView{ID: e.ID, At: e.At, Kind: e.Kind, IP: e.IP, ActorID: e.ActorID, UserAgent: e.UserAgent, Detail: e.Detail}
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "next_cursor": next})
}

func (s *Server) hTokenStats(w http.ResponseWriter, r *http.Request) {
	p, ok := s.authn(w, r)
	if !ok {
		return
	}
	st, err := s.Svc.TokenStats(r.Context(), p, r.PathValue("id"))
	if err != nil {
		s.writeProblem(w, r, err)
		return
	}
	s.writeJSON(w, 200, viewStats(st))
}

var eventKinds = map[string]bool{
	"created": true, "revoked": true, "renamed": true, "expiry_changed": true, "cidr_changed": true,
	"first_use": true, "new_ip": true, "denied_ip": true, "denied_expired": true, "denied_revoked": true,
}

func validEventKind(k string) bool { return eventKinds[k] }
