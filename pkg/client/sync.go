// SPDX-License-Identifier: 0BSD

package client

import (
	"context"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// State is the plan outcome of a sync comparison.
type PlanState int

// Sync states.
const (
	NoRemote PlanState = iota
	InSync
	LocalChanged
	RemoteChanged
	Conflict
)

// Plan summarizes the difference between local and remote.
type Plan struct {
	State              PlanState
	RemoteHead         string
	AddedLocal         []string
	ChangedLocal       []string
	DeletedLocal       []string
	LocalBytes         int64
	RemoteManifestHash api.Hash
	// LocalNewest and RemoteNewest are the newest file mtimes on
	// each side, used by KeepNewest (ties keep remote).
	LocalNewest  int64
	RemoteNewest int64
}

// Plan inspects local vs remote without mutating anything.
func (c *Client) Plan(ctx context.Context, app, slot string, src Source, st StateStore) (*Plan, error) {
	return c.PlanFrom(ctx, c.remote(), app, slot, src, st)
}

// PlanFrom plans against an arbitrary Remote.
func (c *Client) PlanFrom(ctx context.Context, r Remote, app, slot string, src Source, st StateStore) (*Plan, error) {
	prev, err := st.Load(app, slot)
	if err != nil {
		return nil, err
	}
	head, err := r.Head(ctx, app, slot)
	if err != nil {
		return nil, err
	}
	p := &Plan{RemoteHead: head}
	if head == "" {
		p.State = NoRemote
		return p, nil
	}
	// Local changes vs state cache.
	files, _, _, err := walkSource(src, DefaultIgnore(), func(Event) {})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	seen := map[string]bool{}
	changed := false
	for _, f := range files {
		seen[f.path] = true
		if f.mtimeNS > p.LocalNewest {
			p.LocalNewest = f.mtimeNS
		}
		if prev == nil || prev.FileCache == nil {
			changed = true
			p.AddedLocal = append(p.AddedLocal, f.path)
			continue
		}
		e, ok := prev.FileCache[f.path]
		if !ok {
			changed = true
			p.AddedLocal = append(p.AddedLocal, f.path)
			continue
		}
		if !fresh(e, f, now) {
			// Rehash: identical content yields identical refs.
			if sameContent(c, ctx, f, e) {
				p.LocalBytes += f.size
				continue
			}
			changed = true
			p.ChangedLocal = append(p.ChangedLocal, f.path)
		}
		p.LocalBytes += f.size
	}
	if prev != nil {
		for path := range prev.FileCache {
			if !seen[path] {
				changed = true
				p.DeletedLocal = append(p.DeletedLocal, path)
			}
		}
	}
	if m, err := r.Manifest(ctx, app, slot, head); err == nil && m != nil {
		for _, f := range m.Files {
			if f.ModTimeNS > p.RemoteNewest {
				p.RemoteNewest = f.ModTimeNS
			}
		}
	}
	remoteChanged := prev == nil || prev.LastSnapshot != head
	switch {
	case changed && remoteChanged:
		p.State = Conflict
	case changed:
		p.State = LocalChanged
	case remoteChanged:
		p.State = RemoteChanged
	default:
		p.State = InSync
	}
	return p, nil
}

// sameContent rechunks f and compares to the cached refs.
func sameContent(c *Client, ctx context.Context, f scanFile, e FileEntry) bool {
	af, refs, inline, err := c.chunkFile(ctx, f, 64<<10)
	if err != nil {
		return false
	}
	_ = af
	if e.Inline {
		return inline != nil && api.HashBytes(inline) == e.InlineHash
	}
	if len(refs) != len(e.Chunks) {
		return false
	}
	for i, r := range refs {
		if r != e.Chunks[i] {
			return false
		}
	}
	return true
}

// ConflictStrategy decides what Sync does on Conflict.
type ConflictStrategy int

// Strategies.
const (
	Fail ConflictStrategy = iota
	KeepLocal
	KeepRemote
	// KeepNewest keeps the side with the newest file mtime; ties
	// keep remote.
	KeepNewest
	Ask
)

// SyncOptions control Sync.
type SyncOptions struct {
	PushOptions
	PullOptions
	OnConflict ConflictStrategy
	// AskFn is called with the plan when OnConflict is Ask; its
	// return value decides the strategy.
	AskFn     func(*Plan) ConflictStrategy
	BackupDir string
}

// SyncResult summarizes a sync.
type SyncResult struct {
	Plan *Plan
	Push *PushResult
	Pull *PullResult
	Noop bool
}

// Sync reconciles local and remote per the plan.
func (c *Client) Sync(ctx context.Context, app, slot string, src Source, st StateStore, opt SyncOptions) (*SyncResult, error) {
	p, err := c.Plan(ctx, app, slot, src, st)
	if err != nil {
		return nil, err
	}
	res := &SyncResult{Plan: p}
	switch p.State {
	case InSync:
		res.Noop = true
	case NoRemote, LocalChanged:
		r, err := c.Push(ctx, app, slot, src, st, opt.PushOptions)
		res.Push = r
		if err != nil {
			return res, err
		}
	case RemoteChanged:
		po := opt.PullOptions
		if po.BackupDir == "" {
			po.BackupDir = opt.BackupDir
		}
		r, err := c.Pull(ctx, app, slot, "", src, st, po)
		res.Pull = r
		if err != nil {
			return res, err
		}
	case Conflict:
		s := opt.OnConflict
		if s == Ask && opt.AskFn != nil {
			s = opt.AskFn(p)
		}
		if s == KeepNewest {
			if p.LocalNewest > p.RemoteNewest {
				s = KeepLocal
			} else {
				s = KeepRemote
			}
		}
		switch s {
		case KeepLocal:
			po := opt.PushOptions
			po.Force = true
			r, err := c.Push(ctx, app, slot, src, st, po)
			res.Push = r
			if err != nil {
				return res, err
			}
		case KeepRemote:
			po := opt.PullOptions
			if po.BackupDir == "" {
				po.BackupDir = opt.BackupDir
			}
			r, err := c.Pull(ctx, app, slot, "", src, st, po)
			res.Pull = r
			if err != nil {
				return res, err
			}
		default:
			return res, &ConflictError{Head: p.RemoteHead}
		}
	}
	return res, nil
}

var _ = api.Manifest{}

// String names the plan state.
func (s PlanState) String() string {
	switch s {
	case NoRemote:
		return "no-remote"
	case InSync:
		return "in-sync"
	case LocalChanged:
		return "local-changed"
	case RemoteChanged:
		return "remote-changed"
	case Conflict:
		return "conflict"
	}
	return "unknown"
}
