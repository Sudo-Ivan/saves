// SPDX-License-Identifier: 0BSD

package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Sudo-Ivan/saves/internal/auth"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
	"github.com/Sudo-Ivan/saves/internal/service"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// openStore opens the meta store from config.
func openStore(cfg *config.Config) (meta.Store, error) {
	switch cfg.Storage.Meta.Driver {
	case "sqlite":
		return meta.Open(context.Background(), "sqlite", cfg.Storage.Meta.SQLite.Path, meta.Options{})
	case "postgres":
		return meta.Open(context.Background(), "postgres", cfg.Storage.Meta.Postgres.DSN, meta.Options{})
	}
	return nil, fmt.Errorf("unknown meta driver %q", cfg.Storage.Meta.Driver)
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// cmdInit writes a fresh config and creates the first admin user.
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "data dir")
	addr := fs.String("addr", "127.0.0.1:8787", "listen addr")
	mode := fs.String("mode", "small", "small|public|ha-example")
	force := fs.Bool("force", false, "overwrite existing config")
	tokFile := fs.String("token-file", "", "write admin token here (0600)")
	pwFile := fs.String("password-file", "", "write admin web password here (0600)")
	if fs.Parse(args) != nil {
		return 2
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	cp := filepath.Join(*dir, "config.json")
	if _, err := os.Stat(cp); err == nil && !*force {
		fmt.Fprintln(os.Stderr, "init: config exists; use -force")
		return 1
	}
	var b []byte
	ipsec := randHex(32)
	websec := randHex(32)
	switch *mode {
	case "small":
		b = []byte(fmt.Sprintf(initCfgSmall, *addr, *dir, *dir, ipsec, websec))
	case "public":
		b = []byte(fmt.Sprintf(initCfgPublic, *addr, *dir, *dir, ipsec, websec))
	case "ha-example":
		b = []byte(fmt.Sprintf(initCfgHA, *addr, ipsec, websec))
	default:
		fmt.Fprintln(os.Stderr, "init: unknown mode", *mode)
		return 2
	}
	if err := os.WriteFile(cp, b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	if *mode == "ha-example" {
		fmt.Println("ha-example wrote a template config; fill postgres/s3 DSNs before serve")
		return 0
	}
	cfg, err := config.Load(cp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init: store:", err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	u, _, err := st.UpsertUser(ctx, "admin", "admin")
	if err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	tid := randHex(8)
	secret := base64.RawURLEncoding.EncodeToString(mustRand(32))
	tok := "sv1_" + tid + "_" + secret
	if err := st.CreateToken(ctx, meta.Token{
		ID: tid, UserID: u.ID, SecretHash: sha256.Sum256([]byte(secret)),
		Name: "admin", Scopes: []string{"read", "write", "admin"}, CreatedAt: time.Now(),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 1
	}
	if *tokFile != "" {
		if err := os.WriteFile(*tokFile, []byte(tok+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		fmt.Println("token written to", *tokFile)
	} else {
		fmt.Println("admin token (show once):", tok)
	}
	// Web credentials for the admin user with a one-time password.
	if cfg.Web.Enabled {
		pw := randPassword(24)
		ph, err := auth.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		if err := st.CreateCredential(ctx, meta.WebCredential{
			UserID: u.ID, Username: "admin", PasswordHash: ph,
			Admin: true, MustChange: true}); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		if *pwFile != "" {
			if err := os.WriteFile(*pwFile, []byte(pw+"\n"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "init:", err)
				return 1
			}
			fmt.Println("web password written to", *pwFile)
		} else {
			fmt.Println("admin web password (show once):", pw)
		}
	}
	return 0
}

// randPassword returns a random base32 password of n characters.
func randPassword(n int) string {
	const alpha = "abcdefghjkmnpqrstvwxyz23456789"
	b := mustRand(n)
	out := make([]byte, n)
	for i := range out {
		out[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(out)
}

// cmdAdmin runs the admin subcommands.
func cmdAdmin(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: savesd admin user|token|invite|stats ...")
		return 2
	}
	cf, err := config.Load(configPath(args))
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		return 1
	}
	st, err := openStore(cf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "admin:", err)
		return 1
	}
	defer st.Close()
	ctx := context.Background()
	sub, rest := args[0], args[1:]
	switch sub {
	case "user":
		return adminUser(ctx, st, rest)
	case "web-user":
		return adminWebUser(ctx, st, rest)
	case "token":
		return adminToken(ctx, cf, st, rest)
	case "fsck":
		if fsck := st.(interface {
			Fsck(context.Context, bool) (meta.FsckReport, error)
		}); true {
			rep, err := fsck.Fsck(ctx, false)
			if err != nil {
				fmt.Fprintln(os.Stderr, "fsck:", err)
				return 1
			}
			if len(rep.Issues) == 0 {
				fmt.Println("clean")
			}
			for _, i := range rep.Issues {
				fmt.Println(i)
			}
		}
		return 0
	case "stats":
		us, err := st.ListUsers(ctx, "", 1000)
		if err != nil {
			return 1
		}
		fmt.Printf("users: %d\n", len(us))
		return 0
	default:
		fmt.Fprintln(os.Stderr, "admin: unknown sub", sub)
		return 2
	}
}

func adminUser(ctx context.Context, st meta.Store, args []string) int {
	if len(args) < 1 {
		return 2
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			return 2
		}
		u, created, err := st.UpsertUser(ctx, args[1], "free")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(u.ID, u.Subject, "created:", created)
		return 0
	case "list":
		us, err := st.ListUsers(ctx, "", 1000)
		if err != nil {
			return 1
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		for _, u := range us {
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", u.ID, u.Subject, u.Tier, u.Disabled)
		}
		_ = w.Flush()
		return 0
	case "set-tier":
		if len(args) < 3 {
			return 2
		}
		tier := args[2]
		return boolErr2(st.UpdateUser(ctx, args[1], meta.UserPatch{Tier: &tier}))
	case "set-quota":
		if len(args) < 3 {
			return 2
		}
		if args[2] == "reset" {
			q := meta.Optional[int64]{Set: true}
			return boolErr2(st.UpdateUser(ctx, args[1], meta.UserPatch{QuotaBytes: &q}))
		}
		sz, err := config.ParseSize(args[2])
		if err != nil {
			return 2
		}
		q := meta.Optional[int64]{Set: true, Value: int64(sz)}
		return boolErr2(st.UpdateUser(ctx, args[1], meta.UserPatch{QuotaBytes: &q}))
	case "show":
		if len(args) < 2 {
			return 2
		}
		u, err := st.GetUser(ctx, args[1])
		if err != nil {
			u, err = st.GetUserBySubject(ctx, args[1])
			if err != nil {
				return 1
			}
		}
		b, _ := json.MarshalIndent(u, "", "  ")
		fmt.Println(string(b))
		return 0
	case "disable", "enable":
		if len(args) < 2 {
			return 2
		}
		disabled := args[0] == "disable"
		_, err := st.UpdateUser(ctx, args[1], meta.UserPatch{Disabled: &disabled})
		if err != nil {
			return 1
		}
		return 0
	case "delete":
		if len(args) < 2 {
			return 2
		}
		if err := st.DeleteUser(ctx, args[1]); err != nil {
			return 1
		}
		return 0
	}
	return 2
}

var initCfgSmall = `{
  "listen": {"addr": "%s", "protocols": ["h1","h2"]},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "closed"},
  "quota": {"allow_unknown_apps": ".*"},
  "auth": {"ip_secret": "%s"},
  "web": {"enabled": true, "secret": "%s", "public_url": ""},
  "sandbox": {"mode": "enforce"},
  "log": {"level": "info"}
}`

var initCfgPublic = `{
  "listen": {"addr": "%s", "protocols": ["h1","h2","h3"],
             "tls": {"mode": "files", "cert_file": "REPLACE/cert.pem", "key_file": "REPLACE/key.pem"}},
  "ops": {"enabled": false},
  "storage": {"meta": {"driver": "sqlite", "sqlite": {"path": "%s/meta.db"}},
              "blob": {"driver": "fs", "fs": {"root": "%s/blobs"}}},
  "registration": {"mode": "invite"},
  "quota": {"allow_unknown_apps": ".*", "tiers": {"free": {"quota_bytes": "10GiB"}}},
  "auth": {"ip_secret": "%s"},
  "web": {"enabled": true, "secret": "%s", "public_url": ""},
  "sandbox": {"mode": "enforce"},
  "log": {"level": "info"}
}`

var initCfgHA = `{
  "listen": {"addr": "%s", "protocols": ["h1","h2","h3"],
             "tls": {"mode": "acme", "acme": {"email": "REPLACE", "hosts": ["REPLACE"]}}},
  "ops": {"enabled": true, "addr": "127.0.0.1:9090"},
  "storage": {"meta": {"driver": "postgres", "postgres": {"dsn": "REPLACE"}},
              "blob": {"driver": "s3", "s3": {"endpoint": "REPLACE", "bucket": "saves", "access_key_file": "REPLACE", "secret_key_file": "REPLACE"}}},
  "registration": {"mode": "invite"},
  "quota": {"allow_unknown_apps": ".*"},
  "auth": {"ip_secret": "%s"},
  "web": {"enabled": true, "secret": "%s", "public_url": ""},
  "sandbox": {"mode": "enforce"},
  "log": {"level": "info"}
}`

func adminToken(ctx context.Context, cf *config.Config, st meta.Store, args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, tokenUsage)
		return 2
	}
	sub, id := args[0], args[1]
	rest := args[2:]
	tc := cf.Auth.Token
	switch sub {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ContinueOnError)
		name := fs.String("name", "", "token name")
		scopes := fs.String("scopes", "read,write", "comma separated scopes")
		apps := fs.String("app", "", "comma separated app allowlist")
		exp := fs.String("expires", "", "30d, 720h, an RFC 3339 time, or none")
		cidr := fs.String("cidr", "", "allowed addresses or CIDRs, comma separated")
		if fs.Parse(rest) != nil {
			return 2
		}
		if *name == "" {
			*name = fs.Arg(0)
		}
		if *name == "" {
			*name = "cli"
		}
		u, err := st.GetUserBySubject(ctx, id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin: user not found")
			return 1
		}
		sc, err := auth.ParseScopes(*scopes)
		if err != nil || sc == 0 {
			fmt.Fprintln(os.Stderr, "admin: invalid scopes")
			return 2
		}
		e, err := cliExpiry(*exp, tc.MaxTTL.Duration(), true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", cliErr(err))
			return 2
		}
		cidrs, err := service.NormalizeCIDRs(splitList(*cidr))
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin:", cliErr(err))
			return 2
		}
		tid := randHex(8)
		secret := base64.RawURLEncoding.EncodeToString(mustRand(32))
		tok := "sv1_" + tid + "_" + secret
		if err := st.CreateToken(ctx, meta.Token{
			ID: tid, UserID: u.ID, SecretHash: sha256.Sum256([]byte(secret)),
			Name: *name, Scopes: splitList(sc.String()), Apps: splitList(*apps),
			AllowedCIDRs: cidrs, ExpiresAt: e, CreatedAt: time.Now(),
		}); err != nil {
			fmt.Fprintln(os.Stderr, "admin: create failed")
			return 1
		}
		cliAudit(ctx, cf, st, tid, u.ID, "created", "cli")
		fmt.Println("token (show once):", tok)
		return 0
	case "list":
		u, err := st.GetUserBySubject(ctx, id)
		if err != nil {
			return 1
		}
		ts, err := st.ListTokens(ctx, u.ID)
		if err != nil {
			return 1
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tSCOPES\tEXPIRES\tADDRESSES\tSTATUS")
		for _, t := range ts {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, strings.Join(t.Scopes, ","),
				fmtTime(t.ExpiresAt), strings.Join(t.AllowedCIDRs, ","), tokenStatus(t))
		}
		_ = w.Flush()
		return 0
	case "show":
		t, err := st.GetToken(ctx, id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin: token not found")
			return 1
		}
		fmt.Printf("id: %s\nuser: %s\nname: %s\nscopes: %s\napps: %s\naddresses: %s\ncreated: %s\nexpires: %s\nlast used: %s\nstatus: %s\n",
			t.ID, t.UserID, t.Name, strings.Join(t.Scopes, ","), strings.Join(t.Apps, ","),
			strings.Join(t.AllowedCIDRs, ","), t.CreatedAt.UTC().Format(time.RFC3339),
			fmtTime(t.ExpiresAt), fmtTime(t.LastUsedAt), tokenStatus(t))
		if stats, err := st.TokenStats(ctx, id); err == nil {
			fmt.Printf("requests: total=%d 24h=%d 7d=%d 30d=%d unique_ips_30d=%d\n",
				stats.Total, stats.Last24h, stats.Last7d, stats.Last30d, stats.UniqueIPs30d)
			for _, c := range stats.TopIPs {
				fmt.Printf("  %s requests=%d last_seen=%s\n", c.IP, c.Requests, c.LastSeen.UTC().Format(time.RFC3339))
			}
			for k, n := range stats.Denied {
				fmt.Printf("denied %s: %d\n", k, n)
			}
		}
		return 0
	case "events":
		fs := flag.NewFlagSet("token events", flag.ContinueOnError)
		kind := fs.String("kind", "", "event kind filter")
		n := fs.Int("n", 50, "number of events")
		if fs.Parse(rest) != nil {
			return 2
		}
		if *n < 1 || *n > 1000 {
			*n = 50
		}
		ev, _, err := st.ListTokenEvents(ctx, id, *kind, "", *n)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin: events failed")
			return 1
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "TIME\tKIND\tADDRESS\tACTOR\tDETAIL")
		for _, e := range ev {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.At.UTC().Format(time.RFC3339), e.Kind, e.IP, e.ActorID, e.Detail)
		}
		_ = w.Flush()
		return 0
	case "set":
		fs := flag.NewFlagSet("token set", flag.ContinueOnError)
		name := fs.String("name", "", "new name")
		exp := fs.String("expires", "", "30d, 720h, an RFC 3339 time, or none")
		cidr := fs.String("cidr", "", "allowed addresses or CIDRs, comma separated, or none")
		if fs.Parse(rest) != nil {
			return 2
		}
		t, err := st.GetToken(ctx, id)
		if err != nil {
			fmt.Fprintln(os.Stderr, "admin: token not found")
			return 1
		}
		if t.RevokedAt != nil {
			fmt.Fprintln(os.Stderr, "admin: token is revoked")
			return 1
		}
		var patch meta.TokenPatch
		seen := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { seen[f.Name] = true })
		if seen["name"] {
			patch.Name = name
		}
		if seen["expires"] {
			e, err := cliExpiry(*exp, tc.MaxTTL.Duration(), false)
			if err != nil {
				fmt.Fprintln(os.Stderr, "admin:", cliErr(err))
				return 2
			}
			patch.ExpiresAt = &e
		}
		if seen["cidr"] {
			list := splitList(*cidr)
			if *cidr == "none" {
				list = nil
			}
			c, err := service.NormalizeCIDRs(list)
			if err != nil {
				fmt.Fprintln(os.Stderr, "admin:", cliErr(err))
				return 2
			}
			patch.CIDRs = &c
		}
		if err := st.UpdateToken(ctx, id, patch); err != nil {
			fmt.Fprintln(os.Stderr, "admin: update failed")
			return 1
		}
		for _, k := range []struct{ flag, kind string }{{"name", "renamed"}, {"expires", "expiry_changed"}, {"cidr", "cidr_changed"}} {
			if seen[k.flag] {
				cliAudit(ctx, cf, st, id, t.UserID, k.kind, "cli")
			}
		}
		fmt.Println("updated; a running server applies the change within auth.token.cache_ttl")
		return 0
	case "revoke":
		t, _ := st.GetToken(ctx, id)
		rc := boolErr(st.RevokeToken(ctx, id))
		if rc == 0 {
			cliAudit(ctx, cf, st, id, t.UserID, "revoked", "cli")
		}
		return rc
	}
	fmt.Fprintln(os.Stderr, tokenUsage)
	return 2
}

// #nosec G101 -- usage text, not a credential
const tokenUsage = `usage: savesd admin token create <subject> [-name N] [-scopes read,write] [-app A,B] [-expires 30d|720h|RFC3339|none] [-cidr ADDR,CIDR]
       savesd admin token list <subject>
       savesd admin token show <id>
       savesd admin token events <id> [-kind K] [-n 50]
       savesd admin token set <id> [-name N] [-expires 30d|RFC3339|none] [-cidr LIST|none]
       savesd admin token revoke <id>`

func splitList(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// cliExpiry parses a CLI expiry value: empty or none means no expiry.
func cliExpiry(v string, maxTTL time.Duration, creating bool) (*time.Time, error) {
	var t *time.Time
	if v != "" && v != "none" {
		if at, err := time.Parse(time.RFC3339, v); err == nil {
			t = &at
		} else {
			d, err := service.ParseTTL(v)
			if err != nil {
				return nil, err
			}
			at := time.Now().Add(d)
			t = &at
		}
	}
	return service.ResolveTokenExpiry(time.Now(), maxTTL, t, creating)
}

func cliErr(err error) string {
	var p *api.Problem
	if errors.As(err, &p) {
		if p.Detail != "" {
			return p.Title + ": " + p.Detail
		}
		return p.Title
	}
	return err.Error()
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func tokenStatus(t meta.Token) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.ExpiresAt != nil && t.ExpiresAt.Before(time.Now()):
		return "expired"
	}
	return "active"
}

// cliAudit records a management event when auditing is enabled.
func cliAudit(ctx context.Context, cf *config.Config, st meta.Store, tokenID, userID, kind, detail string) {
	if !cf.Auth.Token.AuditEnabled {
		return
	}
	id, err := meta.NewID(time.Now())
	if err != nil {
		return
	}
	_ = st.InsertTokenEvent(ctx, meta.TokenEvent{ID: id, TokenID: tokenID, UserID: userID, At: time.Now(), Kind: kind, Detail: detail})
}

// adminWebUser manages web sign-in credentials.
func adminWebUser(ctx context.Context, st meta.Store, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: savesd admin web-user set-password|reset-2fa ...")
		return 2
	}
	switch args[0] {
	case "set-password":
		fs := flag.NewFlagSet("web-user set-password", flag.ContinueOnError)
		uname := fs.String("username", "", "web username for a new credential")
		isAdmin := fs.Bool("admin", false, "grant web admin")
		pwFile := fs.String("password-file", "", "read the password from this file")
		if fs.Parse(args[1:]) != nil || fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "usage: savesd admin web-user set-password <username|user-id|subject> [-username NAME] [-admin] [-password-file FILE]")
			return 2
		}
		who := fs.Arg(0)
		var pw string
		if *pwFile != "" {
			b, err := os.ReadFile(*pwFile) // #nosec G304 -- operator supplied path
			if err != nil {
				fmt.Fprintln(os.Stderr, "set-password:", err)
				return 1
			}
			pw = strings.TrimSpace(string(b))
		} else {
			pw = readPasswordLine(os.Stdin)
		}
		if err := auth.CheckPasswordPolicy(pw, strings.ToLower(who)); err != nil {
			fmt.Fprintln(os.Stderr, "set-password: password does not meet policy")
			return 1
		}
		ph, err := auth.HashPassword(pw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "set-password:", err)
			return 1
		}
		// Resolve who: username, then user id, then subject.
		cred, err := st.GetCredentialByUsername(ctx, strings.ToLower(who))
		if err == nil {
			no := false
			return boolErr(st.UpdateCredential(ctx, cred.UserID, meta.CredentialPatch{
				PasswordHash: &ph, MustChange: &no}))
		}
		u, err := st.GetUser(ctx, who)
		if err != nil {
			u, err = st.GetUserBySubject(ctx, who)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "set-password: unknown user")
			return 1
		}
		name := *uname
		if name == "" {
			name = strings.ToLower(who)
		}
		err = st.CreateCredential(ctx, meta.WebCredential{
			UserID: u.ID, Username: name, PasswordHash: ph, Admin: *isAdmin})
		if err != nil {
			fmt.Fprintln(os.Stderr, "set-password:", err)
			return 1
		}
		fmt.Println("credential set for", name)
		return 0
	case "reset-2fa":
		if len(args) < 2 {
			return 2
		}
		who := strings.ToLower(args[1])
		cred, err := st.GetCredentialByUsername(ctx, who)
		if err != nil {
			// Resolve like set-password does: user id, then subject,
			// then the credential on that user.
			u, uerr := st.GetUser(ctx, who)
			if uerr != nil {
				u, uerr = st.GetUserBySubject(ctx, who)
			}
			if uerr != nil {
				fmt.Fprintln(os.Stderr, "reset-2fa: unknown user")
				return 1
			}
			cred, err = st.GetCredential(ctx, u.ID)
			if err != nil {
				fmt.Fprintln(os.Stderr, "reset-2fa: no credential for user")
				return 1
			}
		}
		no := false
		empty := []byte{}
		zero := int64(0)
		return boolErr(st.UpdateCredential(ctx, cred.UserID, meta.CredentialPatch{
			TOTPSecret: &empty, TOTPEnabled: &no, TOTPLastStep: &zero}))
	}
	return 2
}

// readPasswordLine reads one line from r without echo support (x/term
// is not a dependency); piped input works, on a terminal the input is
// visible, which the usage text documents.
func readPasswordLine(r io.Reader) string {
	fmt.Fprint(os.Stderr, "Password: ")
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		return ""
	}
	return sc.Text()
}

func boolErr(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func boolErr2(u meta.User, err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
