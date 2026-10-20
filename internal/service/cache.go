// SPDX-License-Identifier: 0BSD

package service

import (
	"container/list"
	"sync"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// manifestCache is a per-process LRU of decoded manifests keyed by
// user and manifest hash, bounded by approximate decoded size.
type manifestCache struct {
	mu    sync.Mutex
	limit int64
	used  int64
	lru   *list.List
	m     map[mcKey]*list.Element
}

type mcKey struct {
	user string
	hash api.Hash
}

type mcEntry struct {
	key  mcKey
	m    api.Manifest
	raw  []byte
	size int64
}

func newManifestCache(limit int64) *manifestCache {
	if limit <= 0 {
		return nil
	}
	return &manifestCache{limit: limit, lru: list.New(), m: map[mcKey]*list.Element{}}
}

func (c *manifestCache) get(user string, h api.Hash) (api.Manifest, []byte, bool) {
	if c == nil {
		return api.Manifest{}, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[mcKey{user, h}]
	if !ok {
		return api.Manifest{}, nil, false
	}
	c.lru.MoveToFront(e)
	en := e.Value.(mcEntry)
	return en.m, en.raw, true
}

func (c *manifestCache) put(user string, h api.Hash, m api.Manifest, raw []byte) {
	if c == nil {
		return
	}
	size := int64(len(raw)) + int64(len(m.Files))*256
	c.mu.Lock()
	defer c.mu.Unlock()
	k := mcKey{user, h}
	if e, ok := c.m[k]; ok {
		c.lru.MoveToFront(e)
		return
	}
	for c.used+size > c.limit && c.lru.Len() > 0 {
		back := c.lru.Back()
		c.used -= back.Value.(mcEntry).size
		delete(c.m, back.Value.(mcEntry).key)
		c.lru.Remove(back)
	}
	if size > c.limit {
		return
	}
	c.m[k] = c.lru.PushFront(mcEntry{key: k, m: m, raw: raw, size: size})
	c.used += size
}
