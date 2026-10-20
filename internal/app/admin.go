// SPDX-License-Identifier: 0BSD

package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/internal/meta"
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
	switch *mode {
	case "small":
		b = []byte(fmt.Sprintf(initCfgSmall, *addr, *dir, *dir, ipsec))
	case "public":
		b = []byte(fmt.Sprintf(initCfgPublic, *addr, *dir, *dir, ipsec))
	case "ha-example":
		b = []byte(fmt.Sprintf(initCfgHA, *addr, ipsec))
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
	return 0
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
	case "token":
		return adminToken(ctx, st, rest)
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
  "sandbox": {"mode": "enforce"},
  "log": {"level": "info"}
}`

func adminToken(ctx context.Context, st meta.Store, args []string) int {
	if len(args) < 2 {
		return 2
	}
	switch args[0] {
	case "create":
		u, err := st.GetUserBySubject(ctx, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		tid := randHex(8)
		secret := base64.RawURLEncoding.EncodeToString(mustRand(32))
		tok := "sv1_" + tid + "_" + secret
		if err := st.CreateToken(ctx, meta.Token{
			ID: tid, UserID: u.ID, SecretHash: sha256.Sum256([]byte(secret)),
			Name: args[2] + "-token", Scopes: []string{"read", "write"},
			CreatedAt: time.Now(),
		}); err != nil {
			return 1
		}
		fmt.Println("token (show once):", tok)
		return 0
	case "list":
		u, err := st.GetUserBySubject(ctx, args[1])
		if err != nil {
			return 1
		}
		ts, err := st.ListTokens(ctx, u.ID)
		if err != nil {
			return 1
		}
		for _, t := range ts {
			fmt.Printf("%s %s %v revoked=%v\n", t.ID, t.Name, t.Scopes, t.RevokedAt != nil)
		}
		return 0
	case "revoke":
		return boolErr(st.RevokeToken(ctx, args[1]))
	}
	return 2
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
