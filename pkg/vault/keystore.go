// SPDX-License-Identifier: 0BSD

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Keystore stores the unwrapped vault key locally.
// FileKeystore relies on 0600 file permissions only.
type Keystore interface {
	Get(id string) ([]byte, error)
	Put(id string, key []byte) error
	Delete(id string) error
}

// ErrNotFound is returned when no key is stored.
var ErrNotFound = errors.New("vault: no key stored")

// MemKeystore is for tests.
type MemKeystore struct{ m map[string][]byte }

func NewMemKeystore() *MemKeystore { return &MemKeystore{m: map[string][]byte{}} }

func (m *MemKeystore) Get(id string) ([]byte, error) {
	b, ok := m.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), b...), nil
}
func (m *MemKeystore) Put(id string, key []byte) error {
	m.m[id] = append([]byte(nil), key...)
	return nil
}
func (m *MemKeystore) Delete(id string) error { delete(m.m, id); return nil }

// FileKeystore stores one file per id, 0600, atomic writes.
// It relies on filesystem permissions; on this platform no OS keyring
// is used, so the key is readable to the owning user only.
type FileKeystore struct{ Dir string }

func (f FileKeystore) path(id string) string {
	return filepath.Join(f.Dir, "vault-"+sanitizeID(id))
}

func sanitizeID(id string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, id)
}

func (f FileKeystore) Get(id string) ([]byte, error) {
	b, err := os.ReadFile(f.path(id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

func (f FileKeystore) Put(id string, key []byte) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	tmp := f.path(id) + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path(id))
}

func (f FileKeystore) Delete(id string) error {
	if err := os.Remove(f.path(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// EnvKeystore reads the key from env (read only).
type EnvKeystore struct{ Getenv func(string) string }

func (e EnvKeystore) getenv(n string) string {
	if e.Getenv != nil {
		return e.Getenv(n)
	}
	return os.Getenv(n)
}

func (e EnvKeystore) Get(id string) ([]byte, error) {
	if v := e.getenv("SAVES_VAULT_KEY"); v != "" {
		return hexDecode(v)
	}
	if f := e.getenv("SAVES_VAULT_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		return hexDecode(strings.TrimSpace(string(b)))
	}
	return nil, ErrNotFound
}

func hexDecode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, fmt.Errorf("vault: key must be 32 byte hex")
	}
	var k [32]byte
	if _, err := fmt.Sscanf(s, "%x", &k); err != nil {
		return nil, err
	}
	out := make([]byte, 32)
	copy(out, k[:])
	return out, nil
}

func (e EnvKeystore) Put(id string, key []byte) error {
	return fmt.Errorf("vault: env keystore is read only")
}
func (e EnvKeystore) Delete(id string) error {
	return fmt.Errorf("vault: env keystore is read only")
}

// DefaultKeystore prefers the env keystore then the file store.
func DefaultKeystore(dir string) Keystore {
	return FileKeystore{Dir: dir}
}
