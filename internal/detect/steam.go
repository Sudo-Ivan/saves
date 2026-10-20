// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// SteamFinder reads steamapps libraries.
type SteamFinder struct{}

// Name returns "steam".
func (SteamFinder) Name() string { return "steam" }

// Find reads libraryfolders.vdf and appmanifest_*.acf.
func (SteamFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var games []Game
	var pfx []WinePrefix
	for _, base := range []string{
		env.Home + "/.steam/steam",
		env.Home + "/.local/share/Steam",
		env.Home + "/.var/app/com.valvesoftware.Steam/.local/share/Steam",
		env.Home + "/snap/steam/common/.local/share/Steam",
	} {
		libs := steamLibraries(fsys, base)
		for _, lib := range libs {
			entries, err := fs.ReadDir(fsys, lib+"/steamapps")
			if err != nil {
				continue
			}
			for _, e := range entries {
				if ctx.Err() != nil {
					return games, pfx, ctx.Err()
				}
				n := e.Name()
				if !strings.HasPrefix(n, "appmanifest_") || !strings.HasSuffix(n, ".acf") {
					continue
				}
				b, err := fs.ReadFile(fsys, lib+"/steamapps/"+n)
				if err != nil {
					continue
				}
				m := parseVDF(string(b))
				appid := m["appid"]
				name := m["name"]
				installdir := m["installdir"]
				if appid == "" || name == "" {
					continue
				}
				dir := lib + "/steamapps/common/" + installdir
				g := Game{ID: "steam:" + appid, Title: name, Store: "steam",
					InstallDir: dir}
				games = append(games, g)
			}
			// Proton compatdata.
			cd, err := fs.ReadDir(fsys, lib+"/steamapps/compatdata")
			if err == nil {
				for _, e := range cd {
					if e.IsDir() {
						pfx = append(pfx, WinePrefix{
							Dir:  lib + "/steamapps/compatdata/" + e.Name(),
							Kind: "proton", Label: "steam " + e.Name()})
					}
				}
			}
		}
	}
	return games, pfx, nil
}

// steamLibraries returns library roots from libraryfolders.vdf.
func steamLibraries(fsys fs.FS, base string) []string {
	b, err := fs.ReadFile(fsys, base+"/steamapps/libraryfolders.vdf")
	if err != nil {
		return []string{base}
	}
	libs := parseVDFList(string(b))
	if len(libs) == 0 {
		libs = []string{base}
	}
	return libs
}

// parseVDF flattens all quoted key:"value" pairs from an acf file,
// descending into nested blocks.
func parseVDF(s string) map[string]string {
	out := map[string]string{}
	toks := vdfTokens(s)
	i := 0
	for i < len(toks) {
		if toks[i] == "{" || toks[i] == "}" {
			i++
			continue
		}
		if i+1 < len(toks) && toks[i+1] == "{" {
			// block: skip key token, descend
			i++
			continue
		}
		if i+1 < len(toks) {
			out[strings.ToLower(toks[i])] = toks[i+1]
			i += 2
			continue
		}
		i++
	}
	return out
}

// parseVDFList returns all "path" values (library roots).
func parseVDFList(s string) []string {
	var out []string
	toks := vdfTokens(s)
	for i := 0; i+1 < len(toks); i++ {
		if toks[i] == "path" || toks[i] == "Path" {
			out = append(out, toks[i+1])
		}
	}
	return out
}

// vdfTokens splits on quotes, keeping braces and quoted strings.
func vdfTokens(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, b.String())
			i = j + 1
		case c == '{' || c == '}':
			out = append(out, string(c))
			i++
		default:
			i++
		}
	}
	return out
}

var _ = strconv.Itoa
var _ = path.Clean
