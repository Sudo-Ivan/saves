// SPDX-License-Identifier: 0BSD

// Package detect finds installed games and their save locations across
// Linux, Windows, Wine/Proton, Lutris, Heroic, Bottles and Minecraft.
package detect

import (
	"context"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Location is one candidate save path for a game.
type Location struct {
	Key         string `json:"key"`   // manifest root key
	Dir         string `json:"dir"`   // local directory
	Rel         string `json:"rel"`   // path inside Dir covered by this location
	Store       string `json:"store"` // steam, gog, epic, minecraft, manual
	Kind        string `json:"kind"`  // save or config
	Exists      bool   `json:"exists"`
	Locked      bool   `json:"locked,omitempty"`
	Prefix      string `json:"prefix"` // wine prefix path when inside one
	Unsupported string `json:"unsupported,omitempty"`
}

// Game is a detected installation.
type Game struct {
	ID         string      `json:"id"`
	Slot       string      `json:"slot"`
	Title      string      `json:"title"`
	Store      string      `json:"store"`
	Known      bool        `json:"known"`
	InstallDir string      `json:"install_dir"`
	Prefix     *WinePrefix `json:"prefix,omitempty"`
	Locations  []Location  `json:"locations"`
}

// WinePrefix is a wine/proton/lutris/bottles prefix.
type WinePrefix struct {
	Dir   string `json:"dir"`
	Kind  string `json:"kind"` // wine, proton, lutris, heroic, bottles
	Label string `json:"label"`
}

// Env supplies host facts for testability.
type Env struct {
	Home       string
	XDGConfig  string
	XDGData    string
	WINEPREFIX string
	OS         string // "linux", "windows"
	Getenv     func(string) string
	// Registry reads windows registry paths; nil on non-windows.
	Registry RegistryReader
}

// RegistryReader abstracts HKCU/HKLM reads.
type RegistryReader interface {
	Get(root, path, name string) (string, error)
	ListKeys(root, path string) ([]string, error)
}

// DefaultEnv returns an Env for the running host.
func DefaultEnv() *Env {
	home, _ := os.UserHomeDir()
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = home + "/.config"
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = home + "/.local/share"
	}
	return &Env{
		Home: home, XDGConfig: cfg, XDGData: data,
		WINEPREFIX: os.Getenv("WINEPREFIX"), OS: "linux",
		Getenv: os.Getenv,
	}
}

// Finder finds games for one store.
type Finder interface {
	Name() string
	Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error)
}

// Detector merges finders.
type Detector struct {
	Finders []Finder
}

// Detect runs finders in parallel, dedups by store+id, sorts.
func (d *Detector) Detect(ctx context.Context, env *Env, fsys fs.FS) ([]Game, error) {
	type out struct {
		g []Game
		p []WinePrefix
	}
	res := make([]out, len(d.Finders))
	var wg sync.WaitGroup
	for i, f := range d.Finders {
		i, f := i, f
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, p, err := f.Find(ctx, env, fsys)
			if err == nil {
				res[i] = out{g, p}
			}
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	var games []Game
	var prefixes []WinePrefix
	for _, r := range res {
		for _, g := range r.g {
			k := g.Store + "/" + g.ID + "/" + g.Slot
			if seen[k] {
				continue
			}
			seen[k] = true
			games = append(games, g)
		}
		prefixes = append(prefixes, r.p...)
	}
	// Attach prefixes to games inside them.
	for i := range games {
		for _, p := range prefixes {
			if strings.HasPrefix(games[i].InstallDir, p.Dir) {
				games[i].Prefix = &p
			}
		}
	}
	sort.Slice(games, func(i, j int) bool {
		if games[i].Store != games[j].Store {
			return games[i].Store < games[j].Store
		}
		return games[i].ID < games[j].ID
	})
	return games, nil
}

// DefaultDetector returns a detector with all finders.
func DefaultDetector() *Detector {
	return &Detector{Finders: []Finder{
		SteamFinder{}, PrefixFinder{}, HeroicFinder{},
		GOGBottles{}, MinecraftFinder{}, ManualFinder{},
	}}
}

// slugify maps arbitrary names to valid app ids and slot names.
func slugify(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == '-' || r == ' ':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" || out[0] < 'a' && out[0] > '9' {
		out = "x" + out
	}
	if len(out) > maxLen {
		out = out[:maxLen]
	}
	return out
}

// slotName returns a valid slot name for a dir name.
func slotName(dir string) string {
	if api.ValidateSlotName(dir) == nil {
		return dir
	}
	return slugify(dir, 56) + "-" + shortHash(dir)
}
