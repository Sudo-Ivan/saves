// SPDX-License-Identifier: 0BSD

package p2p

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Peer is a paired device.
type Peer struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Addrs    []string  `json:"addrs"`
	AddedAt  time.Time `json:"added_at"`
	LastSeen time.Time `json:"last_seen"`
}

// PeerSet is the trusted peers store.
type PeerSet struct {
	mu    sync.RWMutex
	path  string
	peers map[string]Peer
}

// LoadPeers opens peers.json in dir.
func LoadPeers(dir string) (*PeerSet, error) {
	ps := &PeerSet{path: filepath.Join(dir, "peers.json"), peers: map[string]Peer{}}
	if b, err := os.ReadFile(ps.path); err == nil {
		_ = json.Unmarshal(b, &ps.peers)
	}
	return ps, nil
}

// Has reports trust.
func (p *PeerSet) Has(id string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.peers[id]
	return ok
}

// Add stores a peer (0600 atomic).
func (p *PeerSet) Add(peer Peer) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.peers[peer.ID] = peer
	return p.save()
}

// Remove deletes a peer.
func (p *PeerSet) Remove(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.peers, id)
	return p.save()
}

// Get returns a peer.
func (p *PeerSet) Get(id string) (Peer, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	peer, ok := p.peers[id]
	return peer, ok
}

// List returns all peers sorted by id.
func (p *PeerSet) List() []Peer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Peer, 0, len(p.peers))
	for _, peer := range p.peers {
		out = append(out, peer)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (p *PeerSet) save() error {
	b, err := json.Marshal(p.peers)
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}
