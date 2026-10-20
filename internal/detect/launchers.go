// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"encoding/json"
	"io/fs"
	"path"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// LutrisFinder reads lutris games/*.yml.
type LutrisFinder struct{}

// Name returns "lutris".
func (LutrisFinder) Name() string { return "lutris" }

// Find parses $XDG_CONFIG/lutris/games/*.yml.
func (LutrisFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var games []Game
	var pfx []WinePrefix
	dir := env.XDGConfig + "/lutris/games"
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, nil, nil
	}
	for _, e := range ents {
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			continue
		}
		var g struct {
			Name   string `yaml:"name"`
			Slug   string `yaml:"slug"`
			Runner string `yaml:"runner"`
			Game   struct {
				Prefix string `yaml:"prefix"`
				Exe    string `yaml:"exe"`
			} `yaml:"game"`
		}
		if yamlUnmarshal(b, &g) != nil || g.Name == "" {
			continue
		}
		inst := g.Game.Exe
		if inst == "" {
			inst = g.Game.Prefix
		}
		gg := Game{ID: "lutris:" + g.Slug, Title: g.Name, Store: "lutris",
			InstallDir: inst}
		if g.Game.Prefix != "" {
			pfx = append(pfx, WinePrefix{Dir: g.Game.Prefix, Kind: "lutris", Label: g.Slug})
		}
		games = append(games, gg)
	}
	return games, pfx, nil
}

// yamlUnmarshal is the minimal subset we need (flat keys, one nested map).
func yamlUnmarshal(b []byte, v any) error {
	return yaml.Unmarshal(b, v)
}

// LauncherInstanceDirs maps launcher -> config file containing game dirs.
var launcherCFgs = []struct {
	name, glob, key string
}{
	{"prism", ".local/share/PrismLauncher/instances/*/instance.cfg", "InstanceDir"},
	{"polymc", ".local/share/PolyMC/instances/*/mmc-pack.json", ""},
	{"multimc", ".local/share/multimc/instances/*/instance.cfg", "InstanceDir"},
	{"atlauncher", ".local/share/ATLauncher/instances/*/instance.cfg", ""},
	{"curseforge", ".config/CurseForge/instances/*/minecraftinstance.json", ""},
	{"gdlauncher", ".config/gdlauncher_next/instances/*", ""},
	{"modrinth", ".local/share/ModrinthApp/profiles/*", ""},
}

// instanceDirs returns minecraft dirs from launcher configs.
func instanceDirs(env *Env, fsys fs.FS) []string {
	var out []string
	for _, l := range launcherCFgs {
		for _, d := range globAll(fsys, toFS(env.Home+"/"+l.glob)) {
			switch l.name {
			case "curseforge":
				if b, err := fs.ReadFile(fsys, d); err == nil {
					var m struct {
						GameDirectory string `json:"gameDirectory"`
					}
					if json.Unmarshal(b, &m) == nil && m.GameDirectory != "" {
						out = append(out, m.GameDirectory+"/saves")
					}
				}
			case "polymc":
				if b, err := fs.ReadFile(fsys, d); err == nil {
					var m struct {
						Components []struct {
							UID string `json:"uid"`
						} `json:"components"`
					}
					if json.Unmarshal(b, &m) == nil {
						out = append(out, path.Dir(d)+"/minecraft/saves")
					}
				}
			case "modrinth":
				if _, err := fs.Stat(fsys, d+"/profile.json"); err == nil {
					out = append(out, d+"/saves")
				}
			case "gdlauncher":
				if _, err := fs.Stat(fsys, d+"/config.json"); err == nil {
					out = append(out, d+"/instance/saves")
				}
			default:
				if b, err := fs.ReadFile(fsys, d); err == nil {
					cfg := map[string]string{}
					for line := range strings.Lines(string(b)) {
						if k, v, ok := strings.Cut(line, "="); ok {
							cfg[strings.TrimSpace(k)] = strings.TrimSpace(v)
						}
					}
					dir := path.Dir(d)
					if gd := cfg["InstanceDir"]; gd != "" {
						dir = gd
					}
					for _, sub := range []string{"/.minecraft/saves", "/minecraft/saves"} {
						if _, err := fs.Stat(fsys, dir+sub); err == nil {
							out = append(out, dir+sub)
						}
					}
				}
			}
		}
	}
	return out
}

// globAll expands one * segment per path.
func globAll(fsys fs.FS, pat string) []string {
	i := strings.Index(pat, "*")
	if i < 0 {
		if _, err := fs.Stat(fsys, pat); err == nil {
			return []string{pat}
		}
		return nil
	}
	prefix := strings.TrimRight(pat[:i], "/")
	rest := pat[i+1:]
	ents, err := fs.ReadDir(fsys, prefix)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		cand := prefix + "/" + e.Name() + rest
		if strings.Contains(rest, "*") {
			out = append(out, globAll(fsys, cand)...)
		} else if _, err := fs.Stat(fsys, cand); err == nil {
			out = append(out, cand)
		}
	}
	return out
}
