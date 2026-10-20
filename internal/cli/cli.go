// SPDX-License-Identifier: 0BSD

// Package cli implements the savesctl command tree.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"time"

	"github.com/Sudo-Ivan/saves/internal/clicfg"
	"github.com/Sudo-Ivan/saves/internal/netx"
	"github.com/Sudo-Ivan/saves/pkg/client"
	"strings"
)

// Exit codes.
const (
	ExOK       = 0
	ExError    = 1
	ExUsage    = 2
	ExConflict = 3
	ExAuth     = 4
	ExQuota    = 5
)

// ExitError carries a desired process exit code.
type ExitError struct {
	Code int
	Err  error
}

// Error returns the message.
func (e *ExitError) Error() string { return e.Err.Error() }

// Usage exit helper.
func usagef(f string, a ...any) error {
	return &ExitError{Code: ExUsage, Err: fmt.Errorf(f, a...)}
}

// Env supplies IO and host facts for testability.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time
	Paths  clicfg.Paths
	// Client makes API clients; nil uses the default.
	Client func(cfg clicfg.Config) (*client.Client, error)
}

// DefaultEnv returns an Env bound to the process.
func DefaultEnv() *Env {
	return &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.Getenv, Now: time.Now, Paths: clicfg.ResolvePaths(os.Getenv)}
}

// Common flags shared by commands.
type common struct {
	json      bool
	configDir string
	server    string
	token     string
	verbose   bool
	yes       bool
}

func (c *common) add(fs *flag.FlagSet) {
	fs.BoolVar(&c.json, "json", false, "machine output")
	fs.StringVar(&c.configDir, "config-dir", "", "config dir override")
	fs.StringVar(&c.server, "server", "", "server url")
	fs.StringVar(&c.token, "token", "", "bearer token")
	fs.BoolVar(&c.verbose, "v", false, "verbose")
	fs.BoolVar(&c.yes, "yes", false, "assume yes")
}

// loadConfig resolves paths and loads config with flag overrides.
func (c *common) loadConfig(env *Env) (*clicfg.Config, clicfg.Paths, error) {
	paths := env.Paths
	if c.configDir != "" {
		paths.Config = c.configDir
	}
	cfg, err := clicfg.Load(paths, env.Getenv)
	if err != nil {
		return nil, paths, err
	}
	if c.server != "" {
		cfg.Server = c.server
	}
	if c.token != "" {
		cfg.Token = c.token
	}
	return cfg, paths, nil
}

// client builds a pkg/client from config.
func (e *Env) clientFor(cfg *clicfg.Config) (*client.Client, error) {
	if e.Client != nil {
		return e.Client(*cfg)
	}
	if cfg.Server == "" {
		return nil, &ExitError{ExAuth, errors.New("no server configured; run savesctl setup")}
	}
	cc := client.Config{
		BaseURL: cfg.Server, Token: cfg.Token,
		Concurrency: cfg.Concurrency,
		HTTP:        &http.Client{Transport: netx.NewTransport()},
	}
	if strings.HasPrefix(cfg.Server, "p2p://") {
		rt, err := p2pTransport(e.Paths.Config, strings.TrimPrefix(cfg.Server, "p2p://"))
		if err != nil {
			return nil, err
		}
		cc.BaseURL = "https://p2p.invalid"
		cc.HTTP = &http.Client{Transport: rt}
	}
	v, err := cipherFor(context.Background(), e, cfg)
	if err != nil {
		return nil, &ExitError{ExAuth, err}
	}
	if v != nil {
		cc.Cipher = v
	}
	return client.New(cc)
}

// clientPlain builds a client without the vault cipher; used by
// vault management commands that must work before a key is cached.
func (e *Env) clientPlain(cfg *clicfg.Config) (*client.Client, error) {
	if e.Client != nil {
		return e.Client(*cfg)
	}
	if cfg.Server == "" {
		return nil, &ExitError{ExAuth, errors.New("no server configured; run savesctl setup")}
	}
	cc := client.Config{
		BaseURL: cfg.Server, Token: cfg.Token,
		Concurrency: cfg.Concurrency,
		HTTP:        &http.Client{Transport: netx.NewTransport()},
	}
	if strings.HasPrefix(cfg.Server, "p2p://") {
		rt, err := p2pTransport(e.Paths.Config, strings.TrimPrefix(cfg.Server, "p2p://"))
		if err != nil {
			return nil, err
		}
		cc.BaseURL = "https://p2p.invalid"
		cc.HTTP = &http.Client{Transport: rt}
	}
	return client.New(cc)
}

// Cmd is a registered command.
type Cmd struct {
	Name  string
	Usage string
	Help  string
	Run   func(ctx context.Context, env *Env, args []string) error
}

// registry maps command paths.
var registry = map[string]*Cmd{}

func reg(name, usage, help string, run func(context.Context, *Env, []string) error) {
	registry[name] = &Cmd{Name: name, Usage: usage, Help: help, Run: run}
}

// Commands returns sorted command names for completion.
func Commands() []string {
	var out []string
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Main dispatches argv.
func Main(ctx context.Context, env *Env, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, helpText())
		return ExUsage
	}
	if args[0] == "help" && len(args) > 1 {
		if c, ok := registry[args[1]]; ok {
			fmt.Fprintf(env.Stdout, "savesctl %s\n\n%s\n", c.Usage, c.Help)
			return ExOK
		}
	}
	cmd := registry[args[0]]
	if cmd == nil {
		fmt.Fprintf(env.Stderr, "unknown command %q\n%s", args[0], helpText())
		return ExUsage
	}
	err := cmd.Run(ctx, env, args[1:])
	return exitCode(err, env)
}

func exitCode(err error, env *Env) int {
	if err == nil {
		return ExOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		fmt.Fprint(env.Stderr, "savesctl: "+ee.Err.Error()+"\n")
		return ee.Code
	}
	var ce *client.ConflictError
	if errors.As(err, &ce) {
		fmt.Fprint(env.Stderr, "savesctl: conflict, head "+ce.Head+"\n")
		return ExConflict
	}
	var qe *client.QuotaError
	if errors.As(err, &qe) {
		fmt.Fprint(env.Stderr, "savesctl: quota exceeded\n")
		return ExQuota
	}
	if errors.Is(err, client.ErrUnauthorized) {
		fmt.Fprint(env.Stderr, "savesctl: unauthorized\n")
		return ExAuth
	}
	fmt.Fprint(env.Stderr, "savesctl: "+err.Error()+"\n")
	return ExError
}

func helpText() string {
	s := "savesctl commands:\n"
	for _, n := range Commands() {
		s += "  " + registry[n].Usage + "\n"
	}
	return s
}

// parseArgs parses flags that may appear before, between or after
// positional arguments. A literal "--" ends flag parsing as usual.
func parseArgs(fs *flag.FlagSet, args []string) error {
	if slices.Contains(args, "--") {
		return fs.Parse(args)
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	return fs.Parse(append([]string{"--"}, pos...))
}
