// SPDX-License-Identifier: 0BSD

package client

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Root maps a manifest key prefix to a local directory so the same
// save restores on another OS or Wine prefix.
type Root struct {
	Key string
	Dir string
}

// Source is the ordered set of roots synced for a slot.
type Source struct {
	Roots []Root
}

// resolve maps a manifest path to (root, relative) or fails.
func (s Source) resolve(path string) (Root, string, bool) {
	for _, r := range s.Roots {
		p := r.Key + "/"
		if strings.HasPrefix(path, p) {
			return r, strings.TrimPrefix(path, p), true
		}
	}
	return Root{}, "", false
}

// join safely produces the local absolute path for a manifest path.
// It refuses key misses and any path escaping the root.
func (s Source) join(path string) (string, error) {
	r, rel, ok := s.resolve(path)
	if !ok {
		return "", errors.New("client: path outside source roots: " + path)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", errors.New("client: path escapes root: " + path)
	}
	return filepath.Join(r.Dir, clean), nil
}

// Validate checks keys are safe path components.
func (s Source) Validate() error {
	if len(s.Roots) == 0 {
		return errors.New("client: empty source")
	}
	for _, r := range s.Roots {
		if r.Key == "" || strings.ContainsAny(r.Key, "/\\") {
			return errors.New("client: bad root key " + r.Key)
		}
		if err := api.ValidatePath(r.Key, 64); err != nil {
			return err
		}
	}
	return nil
}
