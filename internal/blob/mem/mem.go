// SPDX-License-Identifier: 0BSD

// Package mem implements an in-memory blob.Store for tests.
package mem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Store is an in-memory blob store.
type Store struct {
	mu   sync.RWMutex
	objs map[string]entry
}

type entry struct {
	data    []byte
	modTime time.Time
}

var _ blob.Store = (*Store)(nil)

// New returns an empty store.
func New() *Store {
	return &Store{objs: map[string]entry{}}
}

// Put implements blob.Store.Put.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64, want *api.Hash) error {
	if err := blob.ValidKey(key); err != nil {
		return err
	}
	if size < 0 {
		return blob.ErrSizeMismatch
	}
	data, err := io.ReadAll(io.LimitReader(r, size+1))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(data)) != size {
		return blob.ErrSizeMismatch
	}
	if want != nil && sha256.Sum256(data) != *want {
		return blob.ErrChecksum
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[key] = entry{data: data, modTime: time.Now()}
	return nil
}

type object struct {
	r    *bytes.Reader
	size int64
}

func (o *object) ReadAt(p []byte, off int64) (int, error) { return o.r.ReadAt(p, off) }
func (o *object) Close() error                            { return nil }
func (o *object) Size() int64                             { return o.size }

// Open implements blob.Store.Open.
func (s *Store) Open(ctx context.Context, key string) (blob.Object, error) {
	if err := blob.ValidKey(key); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.objs[key]
	if !ok {
		return nil, blob.ErrNotFound
	}
	return &object{r: bytes.NewReader(e.data), size: int64(len(e.data))}, nil
}

// Stat implements blob.Store.Stat.
func (s *Store) Stat(ctx context.Context, key string) (int64, error) {
	if err := blob.ValidKey(key); err != nil {
		return 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.objs[key]
	if !ok {
		return 0, blob.ErrNotFound
	}
	return int64(len(e.data)), nil
}

// Delete implements blob.Store.Delete.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := blob.ValidKey(key); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objs, key)
	return nil
}

// List implements blob.Store.List.
func (s *Store) List(ctx context.Context, prefix string, fn func(blob.Entry) error) error {
	s.mu.RLock()
	var keys []string
	for k := range s.objs {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	s.mu.RUnlock()
	for _, k := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.RLock()
		e := s.objs[k]
		s.mu.RUnlock()
		if err := fn(blob.Entry{Key: k, Size: int64(len(e.data)), ModTime: e.modTime}); err != nil {
			return err
		}
	}
	return nil
}

// Close implements blob.Store.Close.
func (s *Store) Close() error { return nil }
