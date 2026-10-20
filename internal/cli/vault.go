// SPDX-License-Identifier: 0BSD

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sudo-Ivan/saves/internal/clicfg"
	"github.com/Sudo-Ivan/saves/pkg/vault"
)

func init() {
	reg("vault", "vault <init|unlock|lock|status|change-passphrase|recovery|verify|disable>", "manage end to end vault",
		func(ctx context.Context, e *Env, args []string) error { return cmdVault(ctx, e, args) })
}

func vaultStateDir(e *Env) string { return filepath.Join(e.Paths.State, "vault") }

func vaultKeyStore(e *Env) vault.Keystore { return vault.DefaultKeystore(vaultStateDir(e)) }

func vaultPass(e *Env, pf string, msg string) (string, error) {
	if pf != "" {
		b, err := os.ReadFile(pf)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if v := e.Getenv("SAVES_VAULT_PASSPHRASE"); v != "" {
		return v, nil
	}
	s, ok := prompt(e, msg)
	if !ok {
		return "", fmt.Errorf("passphrase required")
	}
	return s, nil
}

// cipherFor builds the client cipher when vault.enabled.
func cipherFor(ctx context.Context, e *Env, cfg *clicfg.Config) (*vault.Vault, error) {
	if !cfg.VaultEnabled {
		return nil, nil
	}
	ks := vaultKeyStore(e)
	if b, err := ks.Get("default"); err == nil && len(b) == 32 {
		var k vault.Key
		copy(k[:], b)
		return vault.New(k), nil
	}
	return nil, fmt.Errorf("vault: key not cached; run savesctl vault unlock")
}

func cmdVault(ctx context.Context, e *Env, args []string) error {
	if len(args) < 1 {
		return usagef("vault: subcommand required")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("vault "+sub, flag.ContinueOnError)
	var c common
	c.add(fs)
	pf := fs.String("passphrase-file", "", "read passphrase from file")
	force := fs.Bool("force", false, "overwrite existing")
	rec := fs.String("recovery", "", "recovery key")
	recFile := fs.String("recovery-file", "", "write recovery key here")
	j := &c.json
	if err := parseArgs(fs, rest); err != nil {
		return usagef("vault %s: %v", sub, err)
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	if cfg.Server == "" {
		return usagef("vault: configure --server first")
	}
	_ = paths
	switch sub {
	case "init":
		return vaultInit(ctx, e, cfg, pf, recFile, force)
	case "unlock":
		return vaultUnlock(ctx, e, cfg, pf, rec)
	case "lock":
		return vaultKeyStore(e).Delete("default")
	case "status":
		return vaultStatus(ctx, e, cfg, j)
	case "change-passphrase":
		return vaultChangePass(ctx, e, cfg, pf)
	case "recovery":
		if len(rest) == 0 || rest[0] != "new" {
			return usagef("vault recovery new")
		}
		return vaultRecoveryNew(ctx, e, cfg)
	case "verify":
		return vaultVerify(ctx, e, cfg)
	case "disable":
		cfg.VaultEnabled = false
		if err := cfg.Save(e.Paths); err != nil {
			return err
		}
		fmt.Fprintln(e.Stdout, "vault disabled; existing snapshots stay encrypted")
		return nil
	default:
		return usagef("vault: unknown %q", sub)
	}
}

func vaultInit(ctx context.Context, e *Env, cfg *clicfg.Config, pf, recFile *string, force *bool) error {
	cl, err := e.clientPlain(cfg)
	if err != nil {
		return err
	}
	hdr, _, err := cl.GetVault(ctx)
	if err != nil {
		return err
	}
	if len(hdr) > 0 && !*force {
		return fmt.Errorf("vault already exists; use --force")
	}
	pass, err := vaultPass(e, *pf, "new passphrase")
	if err != nil || pass == "" {
		return fmt.Errorf("passphrase required")
	}
	v, recKey, header, err := vault.Create(pass, vault.DefaultKDF)
	if err != nil {
		return err
	}
	if _, err := cl.PutVault(ctx, header, ""); err != nil {
		return err
	}
	k := v.RootKey()
	if err := vaultKeyStore(e).Put("default", k[:]); err != nil {
		return err
	}
	cfg.VaultEnabled = true
	if err := cfg.Save(e.Paths); err != nil {
		return err
	}
	if *recFile != "" {
		if err := os.WriteFile(*recFile, []byte(recKey+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Fprintln(e.Stdout, "recovery key written to", *recFile)
	} else {
		fmt.Fprintln(e.Stdout, "recovery key (save once, never shown again):", recKey)
	}
	fmt.Fprintln(e.Stdout, "vault initialized, kid", v.KID())
	return nil
}

func vaultUnlock(ctx context.Context, e *Env, cfg *clicfg.Config, pf, rec *string) error {
	cl, err := e.clientPlain(cfg)
	if err != nil {
		return err
	}
	hdr, _, err := cl.GetVault(ctx)
	if err != nil {
		return err
	}
	if len(hdr) == 0 {
		return fmt.Errorf("vault: no header on server")
	}
	var v *vault.Vault
	if *rec != "" {
		v, err = vault.UnlockRecovery(hdr, *rec)
	} else {
		pass, e2 := vaultPass(e, *pf, "passphrase")
		if e2 != nil {
			return e2
		}
		v, err = vault.Unlock(hdr, pass)
	}
	if err != nil {
		return &ExitError{ExAuth, err}
	}
	k := v.RootKey()
	if err := vaultKeyStore(e).Put("default", k[:]); err != nil {
		return err
	}
	cfg.VaultEnabled = true
	if err := cfg.Save(e.Paths); err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, "unlocked, kid", v.KID())
	return nil
}

func vaultStatus(ctx context.Context, e *Env, cfg *clicfg.Config, j *bool) error {
	cl, err := e.clientPlain(cfg)
	if err != nil {
		return err
	}
	hdr, etag, _ := cl.GetVault(ctx)
	kb, kerr := vaultKeyStore(e).Get("default")
	cached := kerr == nil && len(kb) == 32
	if *j {
		fmt.Fprintf(e.Stdout, `{"enabled":%v,"key_cached":%v,"header_bytes":%d,"etag":%q}`+"\n",
			cfg.VaultEnabled, cached, len(hdr), etag)
		return nil
	}
	fmt.Fprintf(e.Stdout, "enabled=%v key_cached=%v header=%dB etag=%s\n",
		cfg.VaultEnabled, cached, len(hdr), etag)
	return nil
}

func vaultChangePass(ctx context.Context, e *Env, cfg *clicfg.Config, pf *string) error {
	cl, err := e.clientPlain(cfg)
	if err != nil {
		return err
	}
	hdr, etag, err := cl.GetVault(ctx)
	if err != nil || len(hdr) == 0 {
		return fmt.Errorf("vault: no header")
	}
	old, err := vaultPass(e, *pf, "current passphrase")
	if err != nil {
		return err
	}
	np, ok := prompt(e, "new passphrase")
	if !ok || np == "" {
		return fmt.Errorf("new passphrase required")
	}
	nh, err := vault.ChangePassphrase(hdr, old, np, vault.DefaultKDF)
	if err != nil {
		return &ExitError{ExAuth, err}
	}
	if _, err := cl.PutVault(ctx, nh, etag); err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, "passphrase changed")
	return nil
}

func vaultRecoveryNew(ctx context.Context, e *Env, cfg *clicfg.Config) error {
	kb, err := vaultKeyStore(e).Get("default")
	if err != nil || len(kb) != 32 {
		return fmt.Errorf("vault: key not cached; unlock first")
	}
	var k vault.Key
	copy(k[:], kb)
	v := vault.New(k)
	cl, err := e.clientPlain(cfg)
	if err != nil {
		return err
	}
	hdr, etag, err := cl.GetVault(ctx)
	if err != nil {
		return err
	}
	rec, nh, err := vault.NewRecovery(hdr, v)
	if err != nil {
		return err
	}
	if _, err := cl.PutVault(ctx, nh, etag); err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, "new recovery key (old is invalid):", rec)
	return nil
}

func vaultVerify(ctx context.Context, e *Env, cfg *clicfg.Config) error {
	ciph, err := cipherFor(ctx, e, cfg)
	if err != nil {
		return err
	}
	if ciph == nil {
		return fmt.Errorf("vault: not enabled")
	}
	fmt.Fprintln(e.Stdout, "vault ok, kid", ciph.KID())
	return nil
}
