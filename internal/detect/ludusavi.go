// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/netx"
	"go.yaml.in/yaml/v3"
)

// ManifestURL is the ludusavi manifest location.
const ManifestURL = "https://raw.githubusercontent.com/mtkennerly/ludusavi-manifest/master/data/manifest.yaml"

const manifestCap = 200 << 20

// DownloadManifest fetches the manifest to dir with ETag revalidation.
func DownloadManifest(ctx context.Context, url, dir string) (string, error) {
	if url == "" {
		url = ManifestURL
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, "manifest.yaml") // #nosec G304 -- dest under caller dir
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	if b, err := os.ReadFile(dest + ".etag"); err == nil { // #nosec G304 -- own cache dir
		req.Header.Set("If-None-Match", string(b))
	}
	c := &http.Client{Transport: netx.NewTransport(), Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 {
		return dest, nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("manifest: http %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, "manifest-*")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, manifestCap)); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if e := resp.Header.Get("ETag"); e != "" {
		_ = os.WriteFile(dest+".etag", []byte(e), 0o600)
	}
	return dest, os.Rename(tmp.Name(), dest)
}

// Entry is the subset of a ludusavi manifest game we use.
type Entry struct {
	Title    string     `json:"t"`
	Steam    string     `json:"s,omitempty"`
	GOG      string     `json:"g,omitempty"`
	Files    []PathRule `json:"f,omitempty"`
	Registry []RegRule  `json:"r,omitempty"`
}

// PathRule is a save path with conditions.
type PathRule struct {
	Path string   `json:"p"`
	Tags []string `json:"t,omitempty"`
	When []When   `json:"w,omitempty"`
}

// RegRule is a registry path rule.
type RegRule struct {
	Path string   `json:"p"`
	Tags []string `json:"t,omitempty"`
}

// When gates a path on os/bit/store.
type When struct {
	OS    string `json:"os,omitempty"`
	Bit   string `json:"bit,omitempty"`
	Store string `json:"store,omitempty"`
}

// Index is the compact parsed manifest.
type Index struct {
	Games     []Entry        `json:"games"`
	BySteam   map[string]int `json:"-"`
	ByTitle   map[string]int `json:"-"`
	ByInstall map[string]int `json:"-"`
}

// ParseManifest decodes a ludusavi manifest.yaml into an Index.
func ParseManifest(r io.Reader) (*Index, error) {
	var raw map[string]struct {
		Steam *struct {
			ID any `yaml:"id"`
		} `yaml:"steam"`
		GOG *struct {
			ID any `yaml:"id"`
		} `yaml:"gog"`
		Files map[string]struct {
			Tags []string `yaml:"tags"`
			When []struct {
				OS    any `yaml:"os"`
				Bit   any `yaml:"bit"`
				Store any `yaml:"store"`
			} `yaml:"when"`
		} `yaml:"files"`
		Registry map[string]struct {
			Tags []string `yaml:"tags"`
		} `yaml:"registry"`
	}
	dec := yaml.NewDecoder(io.LimitReader(r, manifestCap))
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	ix := &Index{BySteam: map[string]int{}, ByTitle: map[string]int{},
		ByInstall: map[string]int{}}
	for name, g := range raw {
		e := Entry{Title: name}
		if g.Steam != nil {
			e.Steam = scalar(g.Steam.ID)
		}
		if g.GOG != nil {
			e.GOG = scalar(g.GOG.ID)
		}
		for p, fr := range g.Files {
			pr := PathRule{Path: p, Tags: fr.Tags}
			for _, w := range fr.When {
				pr.When = append(pr.When, When{
					OS: scalar(w.OS), Bit: scalar(w.Bit), Store: scalar(w.Store)})
			}
			e.Files = append(e.Files, pr)
		}
		for p, rr := range g.Registry {
			e.Registry = append(e.Registry, RegRule{Path: p, Tags: rr.Tags})
		}
		ix.Games = append(ix.Games, e)
	}
	for i, g := range ix.Games {
		if g.Steam != "" {
			ix.BySteam[g.Steam] = i
		}
		ix.ByTitle[normTitle(g.Title)] = i
		ix.ByInstall[normTitle(g.Title)] = i
	}
	return ix, nil
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%d", int64(t))
	}
	return ""
}

func normTitle(s string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s))
}

// Save writes a compact JSON index.
func (ix *Index) Save(path string) error {
	b, err := json.Marshal(ix.Games)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadIndex reads a saved index and rebuilds lookup maps.
func LoadIndex(path string) (*Index, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- caller-supplied cache path
	if err != nil {
		return nil, err
	}
	var g []Entry
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, err
	}
	ix := &Index{Games: g, BySteam: map[string]int{},
		ByTitle: map[string]int{}, ByInstall: map[string]int{}}
	for i, e := range g {
		if e.Steam != "" {
			ix.BySteam[e.Steam] = i
		}
		ix.ByTitle[normTitle(e.Title)] = i
	}
	return ix, nil
}

// Lookup finds the best manifest match for a detected game.
func (ix *Index) Lookup(g Game) (*Entry, bool) {
	for _, l := range g.Locations {
		_ = l
	}
	if g.Store == "steam" {
		if i, ok := ix.BySteam[strings.TrimPrefix(g.ID, "steam:")]; ok {
			return &ix.Games[i], true
		}
	}
	if i, ok := ix.ByTitle[normTitle(g.Title)]; ok {
		return &ix.Games[i], true
	}
	return nil, false
}

// Placeholders supported per ludusavi docs.
var placeholders = map[string]func(*Env, expandCtx) string{
	"root":            func(e *Env, c expandCtx) string { return c.installDir },
	"game":            func(e *Env, c expandCtx) string { return c.installDir },
	"base":            func(e *Env, c expandCtx) string { return c.installDir },
	"home":            func(e *Env, c expandCtx) string { return e.Home },
	"storeuserdir":    func(e *Env, c expandCtx) string { return c.installDir },
	"osusername":      func(e *Env, c expandCtx) string { return "user" },
	"winappdata":      func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/users/user/AppData/Roaming" },
	"winlocalappdata": func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/users/user/AppData/Local" },
	"windocuments":    func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/users/user/Documents" },
	"winpublic":       func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/users/Public" },
	"winprogramdata":  func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/ProgramData" },
	"userprofile":     func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/users/user" },
	"xdgdata":         func(e *Env, c expandCtx) string { return e.XDGData },
	"xdgconfig":       func(e *Env, c expandCtx) string { return e.XDGConfig },
	"savedgames":      func(e *Env, c expandCtx) string { return c.prefix + "/drive_c/users/user/Saved Games" },
}

type expandCtx struct {
	installDir string
	prefix     string
	store      string
	os         string
	bit        string
}

var phRE = regexp.MustCompile(`<([a-zA-Z]+)>`)

// ExpandTemplate replaces <placeholders> and returns the concrete
// path plus whether the rule applies to this os/store.
func ExpandTemplate(t string, env *Env, c expandCtx) (string, bool) {
	// If the template starts with a placeholder, the result must
	// stay inside that placeholder's root.
	var anchor string
	if m := phRE.FindString(t); m != "" && strings.HasPrefix(t, m) {
		k := strings.ToLower(m[1 : len(m)-1])
		if fn, ok := placeholders[k]; ok {
			anchor = fn(env, c)
		}
	}
	out := phRE.ReplaceAllStringFunc(t, func(m string) string {
		k := strings.ToLower(m[1 : len(m)-1])
		if fn, ok := placeholders[k]; ok {
			return fn(env, c)
		}
		return m
	})
	out = filepath.Clean(filepath.FromSlash(out))
	if strings.HasPrefix(out, "..") || strings.Contains(out, string(filepath.Separator)+".."+string(filepath.Separator)) {
		return "", false
	}
	if anchor != "" {
		rel, err := filepath.Rel(anchor, out)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", false
		}
	}
	return out, true
}

// MatchWhen reports whether a When set applies.
func MatchWhen(ws []When, c expandCtx) bool {
	if len(ws) == 0 {
		return true
	}
	for _, w := range ws {
		if w.OS != "" && w.OS != c.os {
			continue
		}
		if w.Bit != "" && w.Bit != c.bit {
			continue
		}
		if w.Store != "" && w.Store != c.store {
			continue
		}
		return true
	}
	return false
}

// ApplyManifest expands a manifest entry into Locations for a game.
func (ix *Index) ApplyManifest(g Game, e *Entry, env *Env, fsys fs.FS) []Location {
	var out []Location
	c := expandCtx{installDir: g.InstallDir, store: g.Store, os: env.OS, bit: "64"}
	if g.Prefix != nil {
		c.prefix = g.Prefix.Dir
	}
	seen := map[string]bool{}
	for _, fr := range e.Files {
		if !MatchWhen(fr.When, c) {
			continue
		}
		save := true
		for _, t := range fr.Tags {
			if t == "config" {
				save = false
			}
		}
		kind := "save"
		if !save {
			kind = "config"
		}
		path, ok := ExpandTemplate(fr.Path, env, c)
		if !ok {
			continue
		}
		// Wildcard expansion: if path contains * glob within parent.
		if strings.ContainsAny(path, "*?") {
			for _, hit := range globWithin(fsys, path) {
				k := "save-" + shortHash(hit)
				if !seen[k] {
					seen[k] = true
					out = append(out, Location{Key: k, Dir: filepath.Dir(hit),
						Rel: filepath.Base(hit), Store: g.Store, Kind: kind, Exists: true})
				}
			}
			continue
		}
		k := "loc-" + shortHash(path)
		if seen[k] {
			continue
		}
		seen[k] = true
		l := Location{Key: k, Dir: path, Store: g.Store, Kind: kind,
			Exists: exists(fsys, path)}
		out = append(out, l)
	}
	for _, rr := range e.Registry {
		out = append(out, Location{Key: "reg-" + shortHash(rr.Path),
			Store: g.Store, Kind: "save", Unsupported: "registry-only"})
	}
	return out
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:4])
}

// globWithin expands a * wildcard in the last path component.
func globWithin(fsys fs.FS, path string) []string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if ok, _ := filepath.Match(base, e.Name()); ok {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
