// SPDX-License-Identifier: 0BSD

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
)

// Version is the build version.
var Version = "dev"

func init() {
	reg("version", "version", "print version", func(ctx context.Context, e *Env, args []string) error {
		fmt.Fprintln(e.Stdout, "savesctl "+Version)
		return nil
	})
	reg("login", "login [--token T | --register] [--server URL]", "set credentials",
		cmdLogin)
	reg("logout", "logout", "clear credentials", cmdLogout)
	reg("me", "me", "show usage and quota", cmdMe)
}

func cmdLogin(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	var c common
	c.add(fs)
	reg := fs.Bool("register", false, "register new account")
	invite := fs.String("invite", "", "invite code")
	if err := fs.Parse(args); err != nil {
		return usagef("login: %v", err)
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	if cfg.Server == "" {
		return &ExitError{ExUsage, fmt.Errorf("no --server and no configured server")}
	}
	if *reg {
		cl, err := e.clientFor(cfg)
		if err != nil {
			return err
		}
		_, tok, err := cl.Register(ctx, *invite)
		if err != nil {
			return err
		}
		cfg.Token = tok
		if err := cfg.Save(paths); err != nil {
			return err
		}
		fmt.Fprintf(e.Stdout, "registered; token: %s\n", tok)
		return nil
	}
	if *invite != "" {
		return &ExitError{ExUsage, fmt.Errorf("--invite requires --register")}
	}
	if cfg.Token == "" {
		return &ExitError{ExUsage, fmt.Errorf("no --token supplied")}
	}
	if err := cfg.Save(paths); err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, "credentials saved")
	return nil
}

func cmdLogout(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := fs.Parse(args); err != nil {
		return usagef("logout: %v", err)
	}
	cfg, paths, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cfg.Token = ""
	if err := cfg.Save(paths); err != nil {
		return err
	}
	fmt.Fprintln(e.Stdout, "logged out")
	return nil
}

func cmdMe(ctx context.Context, e *Env, args []string) error {
	fs := flag.NewFlagSet("me", flag.ContinueOnError)
	var c common
	c.add(fs)
	if err := fs.Parse(args); err != nil {
		return usagef("me: %v", err)
	}
	cfg, _, err := c.loadConfig(e)
	if err != nil {
		return err
	}
	cl, err := e.clientFor(cfg)
	if err != nil {
		return err
	}
	me, err := cl.Me(ctx)
	if err != nil {
		return err
	}
	if c.json {
		return json.NewEncoder(e.Stdout).Encode(me)
	}
	var usage struct {
		Used  int64 `json:"used"`
		Limit int64 `json:"limit"`
	}
	_ = json.Unmarshal(me.Usage, &usage)
	fmt.Fprintf(e.Stdout, "tier: %s\nusage: %d / %d bytes\n", me.Tier, usage.Used, usage.Limit)
	return nil
}
