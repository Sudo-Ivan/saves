// SPDX-License-Identifier: 0BSD

// Package clicfg holds savesctl paths and config.
package clicfg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Paths are the resolved savesctl directories.
type Paths struct {
	Config string
	State  string
	Cache  string
}

// ResolvePaths returns dirs honoring SAVES_*_DIR overrides.
func ResolvePaths(getenv func(string) string) Paths {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := getenv("SAVES_CONFIG_DIR")
	st := getenv("SAVES_STATE_DIR")
	ca := getenv("SAVES_CACHE_DIR")
	home, _ := os.UserHomeDir()
	if cfg == "" {
		switch runtime.GOOS {
		case "windows":
			cfg = filepath.Join(getenv("APPDATA"), "saves")
		case "darwin":
			cfg = filepath.Join(home, "Library", "Application Support", "saves")
		default:
			base := getenv("XDG_CONFIG_HOME")
			if base == "" {
				base = filepath.Join(home, ".config")
			}
			cfg = filepath.Join(base, "saves")
		}
	}
	if st == "" {
		if runtime.GOOS == "windows" {
			st = filepath.Join(getenv("LOCALAPPDATA"), "saves", "state")
		} else {
			base := getenv("XDG_STATE_HOME")
			if base == "" {
				base = filepath.Join(home, ".local", "state")
			}
			st = filepath.Join(base, "saves")
		}
	}
	if ca == "" {
		if runtime.GOOS == "windows" {
			ca = filepath.Join(getenv("LOCALAPPDATA"), "saves", "cache")
		} else {
			base := getenv("XDG_CACHE_HOME")
			if base == "" {
				base = filepath.Join(home, ".cache")
			}
			ca = filepath.Join(base, "saves")
		}
	}
	return Paths{Config: cfg, State: st, Cache: ca}
}

// Tracked is one configured game.
type Tracked struct {
	App        string            `json:"app"`
	Slot       string            `json:"slot"`
	Title      string            `json:"title"`
	Mode       string            `json:"mode"` // auto|manual
	Roots      map[string]string `json:"roots,omitempty"`
	Enabled    bool              `json:"enabled"`
	OnConflict string            `json:"on_conflict"` // ask|keep-local|keep-remote|keep-newest|fail
}

// Config is config.json.
type Config struct {
	Server         string    `json:"server"`
	Token          string    `json:"token,omitempty"`
	TokenFile      string    `json:"token_file,omitempty"`
	TokenEnv       string    `json:"token_env,omitempty"`
	DeviceName     string    `json:"device_name"`
	DeviceID       string    `json:"device_id"`
	Protocol       string    `json:"protocol"` // auto|h2|h3
	Concurrency    int       `json:"concurrency"`
	BandwidthLimit int64     `json:"bandwidth_limit"`
	BackupsKeep    int       `json:"backups_keep"`
	ManifestURL    string    `json:"ludusavi_manifest_url,omitempty"`
	IncludeConfig  bool      `json:"include_config_files"`
	Ignore         []string  `json:"ignore"`
	Tracked        []Tracked `json:"tracked"`
}

// Validate enforces strictness.
func (c *Config) Validate() error {
	if c.BackupsKeep == 0 {
		c.BackupsKeep = 10
	}
	if c.Protocol == "" {
		c.Protocol = "auto"
	}
	for i := range c.Tracked {
		t := &c.Tracked[i]
		if t.Slot == "" {
			t.Slot = "default"
		}
		if t.Mode == "" {
			t.Mode = "auto"
		}
		if t.OnConflict == "" {
			t.OnConflict = "ask"
		}
	}
	return nil
}

// Load reads config.json strictly; missing file returns defaults.
func Load(paths Paths, getenv func(string) string) (*Config, error) {
	p := filepath.Join(paths.Config, "config.json")
	b, err := os.ReadFile(p) // #nosec G304 -- config path under our dir
	if errors.Is(err, os.ErrNotExist) {
		c := &Config{DeviceID: newID()}
		return c, c.Validate()
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if c.DeviceID == "" {
		c.DeviceID = newID()
	}
	// env overrides
	if getenv == nil {
		getenv = os.Getenv
	}
	if v := getenv("SAVES_SERVER"); v != "" {
		c.Server = v
	}
	if v := getenv("SAVES_TOKEN"); v != "" {
		c.Token = v
	}
	if c.TokenEnv != "" {
		if v := getenv(c.TokenEnv); v != "" {
			c.Token = v
		}
	}
	if c.TokenFile != "" {
		// #nosec G304 -- user-configured token file
		if b, err := os.ReadFile(c.TokenFile); err == nil {
			c.Token = string(bytes.TrimSpace(b))
		}
	}
	return &c, c.Validate()
}

// Save writes config.json atomically with mode 0600.
func (c *Config) Save(paths Paths) error {
	if err := os.MkdirAll(paths.Config, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(paths.Config, "config.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Redacted returns a copy safe to print.
func (c *Config) Redacted() *Config {
	r := *c
	if r.Token != "" {
		r.Token = "(set)"
	}
	return &r
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "dev-" + hex.EncodeToString(b)
}

// GameRef parses "app[/slot]".
func GameRef(s string) (app, slot string, err error) {
	app = s
	slot = "default"
	if i := strings.LastIndex(s, "/"); i >= 0 {
		app, slot = s[:i], s[i+1:]
	}
	if app == "" || slot == "" {
		return "", "", fmt.Errorf("bad game ref %q", s)
	}
	return app, slot, nil
}
