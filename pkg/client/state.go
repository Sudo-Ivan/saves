// SPDX-License-Identifier: 0BSD

package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// FileEntry is the cached per-file state from the last sync.
type FileEntry struct {
	Size       int64          `json:"size"`
	ModTimeNS  int64          `json:"mtime_ns"`
	Mode       uint32         `json:"mode"`
	Chunks     []api.ChunkRef `json:"chunks,omitempty"`
	Inline     bool           `json:"inline,omitempty"`
	SealedSize int64          `json:"sealed_size,omitempty"`
	InlineHash api.Hash       `json:"inline_hash,omitempty"`
}

// State is the persisted sync state of a slot.
type State struct {
	DeviceID         string               `json:"device_id"`
	LastSnapshot     string               `json:"last_snapshot"`
	LastManifestHash api.Hash             `json:"manifest_hash"`
	FileSig          string               `json:"file_sig,omitempty"`
	FileCache        map[string]FileEntry `json:"files,omitempty"`
	// ContentSig is a deterministic hash over the plaintext tree for
	// encrypted slots, used to skip unchanged pushes.
	ContentSig string `json:"content_sig,omitempty"`
}

// StateStore persists per-slot state outside the save dirs.
type StateStore interface {
	Load(app, slot string) (*State, error)
	Save(app, slot string, st *State) error
}

// FileStore is a JSON StateStore in dir (0600 files, atomic writes).
type FileStore struct {
	Dir string
}

// MemStore is an in-memory StateStore for tests.
type MemStore struct {
	mu sync.Mutex
	m  map[string]State
}

// NewMemStore returns a MemStore.
func NewMemStore() *MemStore { return &MemStore{m: map[string]State{}} }

func (s *MemStore) key(app, slot string) string { return app + "/" + slot }

// Load implements StateStore.
func (s *MemStore) Load(app, slot string) (*State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[s.key(app, slot)]
	if !ok {
		return nil, nil
	}
	out := st
	return &out, nil
}

// Save implements StateStore.
func (s *MemStore) Save(app, slot string, st *State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[s.key(app, slot)] = *st
	return nil
}

func (f FileStore) path(app, slot string) string {
	return filepath.Join(f.Dir, app+"_"+slot+".json")
}

// Load implements StateStore.
func (f FileStore) Load(app, slot string) (*State, error) {
	b, err := os.ReadFile(f.path(app, slot))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Save implements StateStore with a temp file plus rename.
func (f FileStore) Save(app, slot string, st *State) error {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := f.path(app, slot) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path(app, slot))
}
