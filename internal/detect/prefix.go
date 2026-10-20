// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
)

// PrefixFinder discovers wine prefixes outside game managers.
type PrefixFinder struct{}

// Name returns "wine-prefix".
func (PrefixFinder) Name() string { return "wine-prefix" }

// Find scans WINEPREFIX env, ~/.wine, lutris, heroic, bottles.
func (PrefixFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var pfx []WinePrefix
	if env.WINEPREFIX != "" {
		pfx = append(pfx, WinePrefix{Dir: env.WINEPREFIX, Kind: "wine", Label: "WINEPREFIX"})
	}
	for _, d := range []string{env.Home + "/.wine"} {
		if _, err := fs.Stat(fsys, d+"/system.reg"); err == nil {
			pfx = append(pfx, WinePrefix{Dir: d, Kind: "wine", Label: "default"})
		}
	}
	return nil, pfx, nil
}

// HeroicFinder reads heroic GamesConfig and legendary installed.json.
type HeroicFinder struct{}

// Name returns "heroic".
func (HeroicFinder) Name() string { return "heroic" }

// Find parses heroic config dirs for gog and epic installs.
func (HeroicFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var games []Game
	var pfx []WinePrefix
	dir := env.XDGConfig + "/heroic"
	// legendary installed.json (epic)
	b, err := fs.ReadFile(fsys, dir+"/legendaryConfig/legendary/installed.json")
	if err == nil {
		var m map[string]struct {
			Title       string `json:"title"`
			InstallPath string `json:"install_path"`
			AppName     string `json:"app_name"`
		}
		if json.Unmarshal(b, &m) == nil {
			for id, g := range m {
				games = append(games, Game{ID: "epic:" + id, Title: g.Title,
					Store: "epic", InstallDir: g.InstallPath})
			}
		}
	}
	// gogdl installed.json
	b, err = fs.ReadFile(fsys, dir+"/gog_store/installed.json")
	if err == nil {
		var m map[string]struct {
			Title       string `json:"title"`
			InstallPath string `json:"install_path"`
			ProductID   string `json:"productId"`
		}
		if json.Unmarshal(b, &m) == nil {
			for id, g := range m {
				pid := id
				if g.ProductID != "" {
					pid = g.ProductID
				}
				games = append(games, Game{ID: "gog:" + pid, Title: g.Title,
					Store: "gog", InstallDir: g.InstallPath})
			}
		}
	}
	// GamesConfig winePrefix discovery.
	ents, err := fs.ReadDir(fsys, dir+"/GamesConfig")
	if err == nil {
		for _, e := range ents {
			b, err := fs.ReadFile(fsys, dir+"/GamesConfig/"+e.Name())
			if err != nil {
				continue
			}
			var gc struct {
				WinePrefix string `json:"winePrefix"`
			}
			if json.Unmarshal(b, &gc) == nil && gc.WinePrefix != "" {
				pfx = append(pfx, WinePrefix{Dir: gc.WinePrefix,
					Kind: "heroic", Label: strings.TrimSuffix(e.Name(), ".json")})
			}
		}
	}
	return games, pfx, nil
}

// GOGBottles reads bottles bottle.yml dirs.
type GOGBottles struct{}

// Name returns "bottles".
func (GOGBottles) Name() string { return "bottles" }

// Find scans ~/.local/share/bottles for bottle.yml files.
func (GOGBottles) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var pfx []WinePrefix
	base := env.XDGData + "/bottles/bottles"
	ents, err := fs.ReadDir(fsys, base)
	if err != nil {
		return nil, nil, nil
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if _, err := fs.Stat(fsys, base+"/"+e.Name()+"/bottle.yml"); err == nil {
			pfx = append(pfx, WinePrefix{Dir: base + "/" + e.Name(),
				Kind: "bottles", Label: e.Name()})
		}
	}
	return nil, pfx, nil
}

// ManualFinder adds games from user config.
type ManualFinder struct {
	// Games comes from savesctl config.
	Games []ManualGame
}

// ManualGame is a user-declared game.
type ManualGame struct {
	Name  string   `json:"name"`
	ID    string   `json:"id"`
	Paths []string `json:"paths"`
}

// Name returns "manual".
func (ManualFinder) Name() string { return "manual" }

// Find returns user-declared games.
func (f ManualFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var out []Game
	for _, g := range f.Games {
		gg := Game{ID: "manual:" + g.ID, Title: g.Name, Store: "manual"}
		for i, p := range g.Paths {
			gg.Locations = append(gg.Locations, Location{
				Key: "p" + strings.Repeat("0", i), Dir: p, Store: "manual",
				Kind: "save", Exists: exists(fsys, p)})
		}
		out = append(out, gg)
	}
	return out, nil, nil
}

func exists(fsys fs.FS, p string) bool {
	_, err := fs.Stat(fsys, p)
	return err == nil
}

var _ = filepath.Join
