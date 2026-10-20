// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"io/fs"
	"path"
	"strings"
)

// MinecraftFinder finds Java and Bedrock worlds.
type MinecraftFinder struct{ ProbeLocks bool }

// Name returns "minecraft".
func (MinecraftFinder) Name() string { return "minecraft" }

var mcDirs = []struct{ kind, dir string }{
	{"java", ".minecraft/saves"},
	{"java", ".var/app/com.mojang.Minecraft/.minecraft/saves"},
	{"java", ".local/share/PrismLauncher/instances/*/minecraft/saves"},
	{"java", ".var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/instances/*/minecraft/saves"},
	{"bedrock", ".local/share/mcpelauncher/games/com.mojang/minecraftWorlds"},
	{"bedrock", ".var/app/io.mrarm.mcpelauncher/data/mcpelauncher/games/com.mojang/minecraftWorlds"},
}

// Find lists world dirs with level.dat.
func (f MinecraftFinder) Find(ctx context.Context, env *Env, fsys fs.FS) ([]Game, []WinePrefix, error) {
	var games []Game
	dirs := append([]string{}, func() []string {
		var o []string
		for _, d := range mcDirs {
			o = append(o, env.Home+"/"+d.dir)
		}
		return o
	}()...)
	dirs = append(dirs, instanceDirs(env, fsys)...)
	for _, base := range dirs {
		if strings.Contains(base, "*") {
			base = globDir(fsys, base)
		}
		ents, err := fs.ReadDir(fsys, toFS(base))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			w := base + "/" + e.Name()
			fsw := toFS(w)
			kind := "java"
			name := e.Name()
			if _, err := fs.Stat(fsys, fsw+"/level.dat"); err != nil {
				if b, err2 := fs.ReadFile(fsys, fsw+"/levelname.txt"); err2 == nil {
					kind = "bedrock"
					name = strings.TrimSpace(string(b))
				} else {
					continue
				}
			}
			g := Game{ID: "minecraft-" + kind, Slot: slotName(e.Name()),
				Title: name, Store: "minecraft", InstallDir: w, Known: true}
			l := Location{Key: "world", Dir: w, Store: "minecraft", Kind: "save", Exists: true}
			if f.ProbeLocks {
				l.Locked = IsWorldLocked(w)
			}
			g.Locations = append(g.Locations, l)
			games = append(games, g)
		}
	}
	return games, nil, nil
}

// globDir resolves the first existing parent of a * path.
func globDir(fsys fs.FS, pat string) string {
	i := strings.Index(pat, "*")
	if i < 0 {
		return pat
	}
	prefix := pat[:i]
	ents, err := fs.ReadDir(fsys, prefix)
	if err != nil {
		return pat
	}
	rest := pat[i+1:]
	for _, e := range ents {
		cand := prefix + e.Name() + rest
		if _, err := fs.Stat(fsys, cand); err == nil {
			return cand
		}
	}
	return pat
}

// toFS converts an absolute OS path to the Detect fs path.
// Finders may get either an os.DirFS("/") style root or a fake FS
// where the home is relative; the Env.Home prefix is stripped when
// it is not a clean fs path.
func toFS(abs string) string {
	return path.Clean(strings.TrimPrefix(abs, "/"))
}

// stripFS exposes absolute OS paths to an fs.FS rooted at /.
type stripFS struct{ fs.FS }

func (stripFS) name(n string) string { return strings.TrimPrefix(n, "/") }

func (f stripFS) Open(name string) (fs.File, error) { return f.FS.Open(f.name(name)) }

// ReadDir strips the leading slash too.
func (f stripFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(f.FS, f.name(name))
}

// Stat strips the leading slash too.
func (f stripFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(f.FS, f.name(name))
}

// ReadFile strips the leading slash too.
func (f stripFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(f.FS, f.name(name))
}

// FS returns an fs.FS where absolute paths work.
func FS(fsys fs.FS) fs.FS { return stripFS{fsys} }
