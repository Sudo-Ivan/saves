// SPDX-License-Identifier: 0BSD

// Package webui embeds the HTML templates and static assets of the
// saves web UI.
package webui

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"sort"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/* static/fonts/*
var staticFS embed.FS

// Static is the embedded asset filesystem.
var Static fs.FS = staticFS

// StaticNames lists the bundled asset file names.
func StaticNames() []string {
	entries, err := staticFS.ReadDir("static")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	// Fonts live in their own directory.
	if fsents, err := staticFS.ReadDir("static/fonts"); err == nil {
		for _, e := range fsents {
			if !e.IsDir() {
				out = append(out, "fonts/"+e.Name())
			}
		}
	}
	sort.Strings(out)
	return out
}

// ReadStatic returns the asset bytes.
func ReadStatic(name string) ([]byte, error) {
	return staticFS.ReadFile("static/" + name)
}

// Fingerprint returns a content hash fragment for asset URLs.
func Fingerprint(name string) string {
	b, err := ReadStatic(name)
	if err != nil {
		return "00000000"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:4])
}

// Parse builds one template set per page: each set holds the shared
// layout plus the named page definitions. name is the file base name
// without extension.
func Parse(funcs template.FuncMap) (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	pages, err := fs.Glob(templateFS, "templates/page_*.html")
	if err != nil {
		return nil, err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/page_"), ".html")
		t, err := template.New(name).Funcs(funcs).
			ParseFS(templateFS, "templates/layout.html", "templates/partial_*.html", p)
		if err != nil {
			return nil, fmt.Errorf("webui: %s: %w", p, err)
		}
		out[name] = t
	}
	return out, nil
}

// Funcs are the shared template helpers.
func Funcs(base string) template.FuncMap {
	return template.FuncMap{
		"asset": func(name string) string {
			i := strings.LastIndexByte(name, '.')
			if i < 0 {
				return base + "static/" + name
			}
			return fmt.Sprintf("%sstatic/%s.%s%s", base, name[:i], Fingerprint(name), name[i:])
		},
		"fdate": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"fdatep": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
		"fsize": fsize,
		"trunc": func(v string, n int) string {
			if len(v) <= n {
				return v
			}
			return v[:n] + "..."
		},
		"eventLabel": eventLabel,
	}
}

func fsize(b int64) string {
	const u = 1024
	switch {
	case b < u:
		return fmt.Sprintf("%d B", b)
	case b < u*u:
		return fmt.Sprintf("%.1f KiB", float64(b)/u)
	case b < u*u*u:
		return fmt.Sprintf("%.1f MiB", float64(b)/(u*u))
	default:
		return fmt.Sprintf("%.2f GiB", float64(b)/(u*u*u))
	}
}

var eventLabels = map[string]string{
	"created": "Created", "revoked": "Revoked", "renamed": "Renamed",
	"expiry_changed": "Expiry changed", "cidr_changed": "Allowed addresses changed",
	"first_use": "First use", "new_ip": "First request from a new address",
	"denied_ip": "Blocked: address not allowed", "denied_expired": "Blocked: token expired",
	"denied_revoked": "Blocked: token revoked",
}

func eventLabel(kind string) string {
	if v, ok := eventLabels[kind]; ok {
		return v
	}
	return "Event"
}
