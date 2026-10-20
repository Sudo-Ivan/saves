// SPDX-License-Identifier: 0BSD

package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// PullOptions control Pull.
type PullOptions struct {
	Ignore    *Ignore
	Delete    bool
	DryRun    bool
	BackupDir string
	OnEvent   func(Event)
	OnlyPaths []string
}

// PullResult summarizes a pull.
type PullResult struct {
	Written    int64
	Bytes      int64
	Chunks     int64
	Downloaded int64
	Deleted    int64
	Skipped    int64
	Duration   time.Duration
}

// writeErrHook, when set, fails the next file write for tests.
var writeErrHook func(string) error

// rootOpen returns an os.Root on dir, creating it.
func rootOpen(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenRoot(dir)
}

// writeFile atomic-writes data under an open root via temp+rename in
// the same directory.
func writeFile(r *os.Root, rel string, data func(w io.Writer) error, mode uint32, mtimeNS int64) error {
	dir := filepath.Dir(rel)
	if dir != "." {
		if err := r.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	name := ".saves-tmp-" + randHex8()
	tmp, err := r.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = r.Remove(filepath.Join(dir, name))
		}
	}()
	if writeErrHook != nil {
		if err := writeErrHook(rel); err != nil {
			return err
		}
	}
	if err := data(tmp); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = r.Chmod(filepath.Join(dir, name), fs.FileMode(mode&0o777))
	_ = r.Chtimes(filepath.Join(dir, name), time.Now(), time.Unix(0, mtimeNS))
	if err := r.Rename(filepath.Join(dir, name), rel); err != nil {
		return err
	}
	ok = true
	return nil
}

// Pull restores a snapshot into the source roots.
func (c *Client) Pull(ctx context.Context, app, slot, snapshot string, src Source, st StateStore, opt PullOptions) (*PullResult, error) {
	return c.PullFrom(ctx, c.remote(), app, slot, snapshot, src, st, opt)
}

// PullFrom pulls from an arbitrary Remote (server or peer).
func (c *Client) PullFrom(ctx context.Context, r Remote, app, slot, snapshot string, src Source, st StateStore, opt PullOptions) (*PullResult, error) {
	if err := src.Validate(); err != nil {
		return nil, err
	}
	ev := opt.OnEvent
	if ev == nil {
		ev = func(Event) {}
	}
	t0 := time.Now()
	if snapshot == "" {
		snapshot = "latest"
	}
	if snapshot == "" {
		h, err := r.Head(ctx, app, slot)
		if err != nil {
			return nil, err
		}
		snapshot = h
	}
	m, err := r.Manifest(ctx, app, slot, snapshot)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m != nil && m.Enc != nil {
		return c.encPullFrom(ctx, r, app, slot, snapshot, m, src, st, opt)
	}
	if m != nil && m.Enc == nil && c.cfg.Cipher != nil {
		// Plaintext snapshot: still pullable with a cipher configured.
	}
	prev, err := st.Load(app, slot)
	if err != nil {
		return nil, err
	}
	only := map[string]bool{}
	for _, p := range opt.OnlyPaths {
		only[p] = true
	}
	// Open one os.Root per source root; rejects keys outside Source.
	roots := map[string]*os.Root{}
	defer func() {
		for _, r := range roots {
			_ = r.Close()
		}
	}()
	for _, rt := range src.Roots {
		r, err := rootOpen(rt.Dir)
		if err != nil {
			return nil, err
		}
		roots[rt.Key] = r
	}
	var backupRoot *os.Root
	if opt.BackupDir != "" {
		backupRoot, err = rootOpen(opt.BackupDir)
		if err != nil {
			return nil, err
		}
		defer backupRoot.Close()
	}

	type pendingFile struct {
		f    api.File
		rel  string
		root *os.Root
		old  *FileEntry
	}
	var pending []pendingFile
	needHash := map[api.Hash]int{}
	var res PullResult
	seen := map[string]bool{}
	for _, f := range m.Files {
		seen[f.Path] = true
		if len(only) > 0 && !only[f.Path] {
			continue
		}
		rt, rel, ok := src.resolve(f.Path)
		if !ok || filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
			ev(Event{Kind: EvSkip, Path: f.Path, Detail: "outside source roots"})
			res.Skipped++
			continue
		}
		rel = filepath.FromSlash(rel)
		root := roots[rt.Key]
		if root == nil {
			ev(Event{Kind: EvSkip, Path: f.Path, Detail: "unknown key"})
			res.Skipped++
			continue
		}
		if prev != nil {
			if e, ok := prev.FileCache[f.Path]; ok {
				if info, err := root.Lstat(rel); err == nil &&
					info.Size() == f.Size && info.ModTime().UnixNano() == f.ModTimeNS &&
					e.Size == f.Size && e.ModTimeNS == f.ModTimeNS {
					continue
				}
			}
		}
		var old *FileEntry
		if prev != nil {
			if e, ok := prev.FileCache[f.Path]; ok {
				old = &e
			}
		}
		have := map[api.Hash]bool{}
		if old != nil {
			for _, r := range old.Chunks {
				have[r.Hash] = true
			}
		}
		for _, r := range f.Chunks {
			if !have[r.Hash] {
				needHash[r.Hash]++
			}
		}
		pending = append(pending, pendingFile{f: f, rel: rel, root: root, old: old})
	}
	// Delete pass for files not in snapshot.
	if opt.Delete && prev != nil {
		for path := range prev.FileCache {
			if seen[path] {
				continue
			}
			rt, rel, ok := src.resolve(path)
			if !ok {
				continue
			}
			rel = filepath.FromSlash(rel)
			root := roots[rt.Key]
			if root == nil {
				continue
			}
			if opt.DryRun {
				res.Deleted++
				continue
			}
			if backupRoot != nil {
				data, err := readRootFile(root, rel)
				if err == nil {
					if err := writeBackup(backupRoot, filepath.Base(rel), data); err != nil {
						ev(Event{Kind: EvSkip, Path: path, Detail: "backup: " + err.Error()})
					} else {
						ev(Event{Kind: EvBackup, Path: path})
					}
				}
			}
			_ = root.Remove(rel)
			res.Deleted++
		}
	}
	if opt.DryRun {
		res.Written = int64(len(pending))
		for _, pf := range pending {
			res.Bytes += pf.f.Size
		}
		return &res, nil
	}
	// Download missing chunks in parallel.
	dl := map[api.Hash][]byte{}
	var dlMu sync.Mutex
	var dlErr error
	sem := make(chan struct{}, c.cfg.Concurrency)
	var wg sync.WaitGroup
	var count int64
	for h := range needHash {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			b, err := c.chunk(ctx, app, h)
			dlMu.Lock()
			defer dlMu.Unlock()
			if err != nil {
				if dlErr == nil {
					dlErr = fmt.Errorf("chunk %x: %w", h, err)
				}
				return
			}
			dl[h] = b
			count += int64(len(b))
		}()
	}
	wg.Wait()
	if dlErr != nil {
		return nil, dlErr
	}
	res.Chunks = int64(len(needHash))
	res.Downloaded = count
	for _, pf := range pending {
		f := pf.f
		var writeTo func(w io.Writer) error
		if f.Inline != nil {
			data := f.Inline
			writeTo = func(w io.Writer) error { _, err := w.Write(data); return err }
		} else {
			chunks := f.Chunks
			old := pf.old
			writeTo = func(w io.Writer) error {
				var oldF *os.File
				var oldOff int64
				openOld := func() (*os.File, int64, error) {
					if oldF != nil {
						return oldF, oldOff, nil
					}
					if old == nil {
						return nil, 0, fmt.Errorf("client: chunk missing")
					}
					fp, err := pf.root.Open(pf.rel)
					if err != nil {
						return nil, 0, err
					}
					oldF = fp
					oldOff = 0
					return oldF, oldOff, nil
				}
				var localOff int64
				for _, r := range chunks {
					if b, ok := dl[r.Hash]; ok {
						if _, err := w.Write(b[:r.Size]); err != nil {
							return err
						}
						localOff += int64(r.Size)
						continue
					}
					// Serve from the local file when the chunk is unchanged.
					if old == nil {
						return fmt.Errorf("client: chunk %x not fetched", r.Hash)
					}
					found := false
					var off int64
					for _, or := range old.Chunks {
						if or.Hash == r.Hash && or.Size == r.Size {
							found = true
							break
						}
						off += int64(or.Size)
					}
					if !found {
						return fmt.Errorf("client: chunk %x not fetched", r.Hash)
					}
					fp, _, err := openOld()
					if err != nil {
						return err
					}
					if _, err := fp.Seek(off, io.SeekStart); err != nil {
						return err
					}
					if _, err := io.CopyN(w, fp, int64(r.Size)); err != nil {
						return err
					}
					localOff += int64(r.Size)
				}
				if oldF != nil {
					_ = oldF.Close()
				}
				return nil
			}
		}
		if backupRoot != nil {
			if data, err := readRootFile(pf.root, pf.rel); err == nil {
				if err := writeBackup(backupRoot, filepath.Base(pf.rel), data); err != nil {
					ev(Event{Kind: EvSkip, Path: f.Path, Detail: "backup: " + err.Error()})
				} else {
					ev(Event{Kind: EvBackup, Path: f.Path})
				}
			}
		}
		if err := writeFile(pf.root, pf.rel, writeTo, f.Mode, f.ModTimeNS); err != nil {
			return nil, err
		}
		ev(Event{Kind: EvWrite, Path: f.Path, Bytes: f.Size})
		res.Written++
		res.Bytes += f.Size
	}
	nst := &State{}
	if prev != nil {
		nst = prev
	}
	if nst.FileCache == nil {
		nst.FileCache = map[string]FileEntry{}
	}
	for _, f := range m.Files {
		ent := FileEntry{Size: f.Size, ModTimeNS: f.ModTimeNS,
			Mode: f.Mode, Chunks: f.Chunks, Inline: f.Inline != nil}
		if f.Inline != nil {
			ent.InlineHash = api.HashBytes(f.Inline)
		}
		nst.FileCache[f.Path] = ent
	}
	if snapshot != "latest" {
		nst.LastSnapshot = snapshot
	} else {
		for s := range mustIter(c.ListSnapshots(ctx, app, slot)) {
			nst.LastSnapshot = s.ID
			break
		}
	}
	_, mh, _ := m.Canonical()
	nst.LastManifestHash = mh
	var hs []hashed
	for _, f := range m.Files {
		ent := nst.FileCache[f.Path]
		hs = append(hs, hashed{file: f, refs: f.Chunks, entry: ent})
	}
	nst.FileSig = fileSig(hs)
	if err := st.Save(app, slot, nst); err != nil {
		return nil, err
	}
	res.Duration = time.Since(t0)
	return &res, nil
}

func readRootFile(r *os.Root, rel string) ([]byte, error) {
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 256<<20))
}

func writeBackup(r *os.Root, name string, data []byte) error {
	tmp, err := r.OpenFile(name+".bak", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}

func mustIter(it func(func(Snapshot) bool), err error) func(func(Snapshot) bool) {
	if it == nil {
		return func(func(Snapshot) bool) {}
	}
	return it
}

// randHex8 makes temp names unpredictable inside the root.
func randHex8() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var _ = errors.Is
