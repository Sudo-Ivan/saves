// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"encoding/json"
	"io/fs"
	"strings"
)

// GOGGalaxyFinder reads HKLM\SOFTWARE\GOG.com\Games via the registry
// interface (Windows) and the 32-bit view fallback.
type GOGGalaxyFinder struct{}

// Name returns "gog".
func (GOGGalaxyFinder) Name() string { return "gog" }

// Find enumerates installed gog games.
func (GOGGalaxyFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	if env.Registry == nil {
		return nil, nil, nil
	}
	var games []Game
	for _, base := range []string{
		`SOFTWARE\GOG.com\Games`,
		`SOFTWARE\WOW6432Node\GOG.com\Games`,
	} {
		keys, err := env.Registry.ListKeys("HKLM", base)
		if err != nil {
			continue
		}
		for _, id := range keys {
			name, _ := env.Registry.Get("HKLM", base+`\`+id, "name")
			path, _ := env.Registry.Get("HKLM", base+`\`+id, "path")
			if path == "" {
				continue
			}
			games = append(games, Game{
				ID: "gog:" + id, Title: name, Store: "gog",
				InstallDir: path,
			})
		}
	}
	return games, nil, nil
}

// EpicItemFinder reads *.item manifests under the Epic manifests dir.
type EpicItemFinder struct{}

// Name returns "epic".
func (EpicItemFinder) Name() string { return "epic" }

// Find parses Epic manifests dir (programdata or heroic legendary).
func (EpicItemFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var games []Game
	for _, dir := range []string{
		env.Getenv("ProgramData") + "/Epic/EpicGamesLauncher/Data/Manifests",
		env.XDGConfig + "/heroic/legendaryConfig/legendary/manifests",
	} {
		if dir == "" {
			continue
		}
		ents, err := fs.ReadDir(fsys, dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".item") {
				continue
			}
			b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
			if err != nil {
				continue
			}
			var m struct {
				DisplayName     string `json:"DisplayName"`
				AppName         string `json:"AppName"`
				InstallLocation string `json:"InstallLocation"`
			}
			if json.Unmarshal(b, &m) != nil || m.AppName == "" {
				continue
			}
			games = append(games, Game{
				ID: "epic:" + m.AppName, Title: m.DisplayName, Store: "epic",
				InstallDir: m.InstallLocation,
			})
		}
	}
	return games, nil, nil
}
