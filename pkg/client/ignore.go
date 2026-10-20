// SPDX-License-Identifier: 0BSD

package client

import (
	"bufio"
	"io"
	"strings"
)

// Ignore is a gitignore-subset matcher: *, **, ?, [..], leading /
// anchor, trailing / dir-only, ! negation. Matching is linear per
// pattern, no regex backtracking.
type Ignore struct {
	pats []ipat
}

type ipat struct {
	neg    bool
	dir    bool
	anchor bool
	parts  []string
}

// ParseIgnore reads patterns from r.
func ParseIgnore(r io.Reader) (*Ignore, error) {
	var ig Ignore
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var p ipat
		if strings.HasPrefix(line, "!") {
			p.neg = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			p.dir = true
			line = strings.TrimSuffix(line, "/")
		}
		if strings.HasPrefix(line, "/") {
			p.anchor = true
			line = strings.TrimPrefix(line, "/")
		}
		if line == "" {
			continue
		}
		p.parts = strings.Split(line, "/")
		ig.pats = append(ig.pats, p)
	}
	return &ig, sc.Err()
}

// DefaultIgnore returns the built-in list.
func DefaultIgnore() *Ignore {
	ig, _ := ParseIgnore(strings.NewReader(
		"*.tmp\n*.bak\nThumbs.db\n.DS_Store\nsession.lock\n"))
	return ig
}

// Match reports whether path (slash separated, relative) is ignored.
// isDir marks directory candidates.
func (ig *Ignore) Match(path string, isDir bool) bool {
	if ig == nil {
		return false
	}
	ignored := false
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, p := range ig.pats {
		if p.dir && !isDir {
			continue
		}
		if matchPat(p, parts, isDir) {
			ignored = !p.neg
		}
	}
	return ignored
}

func matchPat(p ipat, parts []string, isDir bool) bool {
	if p.anchor {
		return matchParts(p.parts, parts)
	}
	// Unanchored: pattern can match at any depth; the final
	// component must match the last path component.
	for i := 0; i <= len(parts)-len(p.parts); i++ {
		if matchParts(p.parts, parts[i:]) {
			return true
		}
	}
	return false
}

// matchParts matches pattern parts against path parts, ** spanning
// zero or more components. Linear time via iteration, not recursion.
func matchParts(pp, sp []string) bool {
	pi, si := 0, 0
	star, save := -1, 0
	for si < len(sp) {
		if pi < len(pp) && (pp[pi] == "**" || globMatch(pp[pi], sp[si])) {
			if pp[pi] == "**" {
				star = pi
				save = si
				pi++
				continue
			}
			pi++
			si++
			continue
		}
		if star >= 0 {
			save++
			si = save
			pi = star + 1
			continue
		}
		return false
	}
	for pi < len(pp) && pp[pi] == "**" {
		pi++
	}
	return pi == len(pp)
}

// globMatch matches a single component pattern using *, ?, [..]
// with a classic two-pointer algorithm. Linear time.
func globMatch(pat, s string) bool {
	pi, si := 0, 0
	star, save := -1, 0
	for si < len(s) {
		if pi < len(pat) && (pat[pi] == '?' || matchSet(pat, pi, s[si])) {
			pi++
			si++
			continue
		}
		if pi < len(pat) && pat[pi] == '*' {
			star = pi
			save = si
			pi++
			continue
		}
		if star >= 0 {
			save++
			si = save
			pi = star + 1
			continue
		}
		return false
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}

// matchSet handles [..] character sets; pi indexes the '['.
func matchSet(pat string, pi int, c byte) bool {
	if pat[pi] != '[' {
		return pat[pi] == c
	}
	j := pi + 1
	neg := false
	if j < len(pat) && (pat[j] == '!' || pat[j] == '^') {
		neg = true
		j++
	}
	in := false
	for j < len(pat) && pat[j] != ']' {
		if j+2 < len(pat) && pat[j+1] == '-' && pat[j+2] != ']' {
			if c >= pat[j] && c <= pat[j+2] {
				in = true
			}
			j += 3
		} else {
			if pat[j] == c {
				in = true
			}
			j++
		}
	}
	return in != neg
}
