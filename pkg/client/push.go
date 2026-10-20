// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
	"github.com/Sudo-Ivan/saves/pkg/cdc"
)

// EventKind enumerates push/pull events.
type EventKind string

// Event kinds.
const (
	EvScan     EventKind = "scan"
	EvSkip     EventKind = "skip"
	EvChunk    EventKind = "chunk"
	EvUpload   EventKind = "upload"
	EvCommit   EventKind = "commit"
	EvWrite    EventKind = "write"
	EvDelete   EventKind = "delete"
	EvBackup   EventKind = "backup"
	EvUnstable EventKind = "unstable"
)

// Event reports progress; emitted on the caller goroutine.
type Event struct {
	Kind   EventKind
	Path   string
	Bytes  int64
	Detail string
}

// PushOptions control Push.
type PushOptions struct {
	Label   string
	Device  string
	Ignore  *Ignore
	Force   bool
	DryRun  bool
	OnEvent func(Event)
}

// PushResult summarizes a push.
type PushResult struct {
	Snapshot      string
	Files         int64
	Dirs          int64
	Bytes         int64
	Chunks        int64
	Uploaded      int64
	Deduped       int64
	BytesUploaded int64
	Duration      time.Duration
	Unchanged     bool
	Skipped       int64
	// SkippedFiles lists each skipped path with its reason.
	SkippedFiles []SkippedFile
}

// scanFile is a file discovered by walking.
type scanFile struct {
	path    string // manifest path
	rel     string // path inside root
	root    *os.Root
	size    int64
	mtimeNS int64
	mode    uint32
}

// walkSource lists files under each root, applying ignore and path
// SkippedFile is a path left out of a push with its reason.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// validation. Files inside a missing root are skipped on push.
func walkSource(src Source, ig *Ignore, ev func(Event)) ([]scanFile, []string, []SkippedFile, error) {
	var files []scanFile
	var dirs []string
	var skipped []SkippedFile
	for _, root := range src.Roots {
		rt, err := os.OpenRoot(root.Dir)
		if err != nil {
			continue // root absent: skipped on push
		}
		err = fs.WalkDir(rt.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == "." {
				return nil
			}
			mpath := root.Key + "/" + filepath.ToSlash(p)
			if d.Type()&fs.ModeSymlink != 0 {
				ev(Event{Kind: EvSkip, Path: mpath, Detail: "symlink"})
				skipped = append(skipped, SkippedFile{Path: p, Reason: "unreadable or excluded"})
				return nil
			}
			if !d.Type().IsRegular() && !d.IsDir() {
				ev(Event{Kind: EvSkip, Path: mpath, Detail: "not a regular file"})
				skipped = append(skipped, SkippedFile{Path: p, Reason: "unreadable or excluded"})
				return nil
			}
			if ig.Match(mpath, d.IsDir()) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if err := api.ValidatePath(mpath, 64); err != nil {
				ev(Event{Kind: EvSkip, Path: mpath, Detail: "invalid path"})
				skipped = append(skipped, SkippedFile{Path: p, Reason: "unreadable or excluded"})
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				dirs = append(dirs, mpath)
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			files = append(files, scanFile{
				path: mpath, rel: p, root: rt,
				size: info.Size(), mtimeNS: info.ModTime().UnixNano(),
				mode: uint32(info.Mode().Perm()),
			})
			return nil
		})
		if err != nil {
			_ = rt.Close()
			return nil, nil, nil, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	sort.Strings(dirs)
	return files, dirs, skipped, nil
}

// fresh reports whether a cached entry still matches (2s mtime
// race window: files modified within 2s are always rehashed).
func fresh(e FileEntry, f scanFile, now time.Time) bool {
	if e.Size != f.size || e.ModTimeNS != f.mtimeNS {
		return false
	}
	if now.UnixNano()-f.mtimeNS < int64(2*time.Second) {
		return false
	}
	return true
}

// chunkFile produces chunk refs and total for one file.
func (c *Client) chunkFile(ctx context.Context, f scanFile, inline int64) (api.File, []api.ChunkRef, []byte, error) {
	if inline > 0 && f.size <= inline {
		fp0, err := f.root.Open(f.rel)
		if err != nil {
			return api.File{}, nil, nil, err
		}
		b, err := io.ReadAll(io.LimitReader(fp0, inline+1))
		_ = fp0.Close()
		if err != nil {
			return api.File{}, nil, nil, err
		}
		return api.File{Path: f.path, Size: f.size, Mode: f.mode,
			ModTimeNS: f.mtimeNS, Inline: b}, nil, b, nil
	}
	fp, err := f.root.Open(f.rel)
	if err != nil {
		return api.File{}, nil, nil, err
	}
	defer fp.Close()
	ch, err := cdc.NewChunker(fp, c.cfg.CDC)
	if err != nil {
		return api.File{}, nil, nil, err
	}
	var refs []api.ChunkRef
	for {
		b, err := ch.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return api.File{}, nil, nil, err
		}
		refs = append(refs, api.ChunkRef{Hash: api.HashBytes(b), Size: uint32(len(b))}) // #nosec G115 -- chunk size bounded by MaxChunkBytes
	}
	return api.File{Path: f.path, Size: f.size, Mode: f.mode,
		ModTimeNS: f.mtimeNS, Chunks: refs}, refs, nil, nil
}

// Push snapshots the source to the server.
func (c *Client) Push(ctx context.Context, app, slot string, src Source, st StateStore, opt PushOptions) (*PushResult, error) {
	if c.cfg.Cipher != nil {
		return c.encPush(ctx, app, slot, src, st, opt)
	}
	if err := src.Validate(); err != nil {
		return nil, err
	}
	ev := opt.OnEvent
	if ev == nil {
		ev = func(Event) {}
	}
	t0 := time.Now()
	ig := opt.Ignore
	if ig == nil {
		ig = DefaultIgnore()
	}
	if ig == nil {
		ig = DefaultIgnore()
	}
	prev, err := st.Load(app, slot)
	if err != nil {
		return nil, err
	}
	if prev == nil {
		prev = &State{DeviceID: opt.Device, FileCache: map[string]FileEntry{}}
	}
	files, dirs, skipped, err := walkSource(src, ig, ev)
	if err != nil {
		return nil, err
	}
	ev(Event{Kind: EvScan, Detail: fmt.Sprintf("%d files", len(files))})

	// Diff against cache to skip unchanged files.
	now := time.Now()
	out := make([]hashed, len(files))
	inlineMax := int64(64 << 10)
	var mfiles int64
	sem := make(chan struct{}, c.cfg.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i, f := range files {
		i, f := i, f
		if e, ok := prev.FileCache[f.path]; ok && fresh(e, f, now) && !e.Inline {
			out[i] = hashed{
				file: api.File{Path: f.path, Size: f.size, Mode: f.mode,
					ModTimeNS: f.mtimeNS, Chunks: e.Chunks},
				refs:  e.Chunks,
				entry: e,
			}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			af, refs, inl, err := c.chunkFile(ctx, f, inlineMax)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			// Re-check mtime after hashing: if it moved, mark unstable.
			if info, err := f.root.Lstat(f.rel); err == nil &&
				info.ModTime().UnixNano() != f.mtimeNS {
				ev(Event{Kind: EvUnstable, Path: f.path, Detail: "changed during hash"})
			}
			ent := FileEntry{
				Size: f.size, ModTimeNS: f.mtimeNS, Mode: f.mode,
				Chunks: refs, Inline: af.Inline != nil,
			}
			if inl != nil {
				ent.InlineHash = api.HashBytes(inl)
			}
			out[i] = hashed{file: af, refs: refs, entry: ent}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	var manifest api.Manifest
	manifest.Version = 1
	manifest.Device = opt.Device
	manifest.Label = opt.Label
	manifest.Parent = prev.LastSnapshot
	manifest.Dirs = dirs
	var totalChunks int64
	uniq := map[api.Hash]int64{}
	newCache := map[string]FileEntry{}
	for _, h := range out {
		manifest.Files = append(manifest.Files, h.file)
		mfiles += h.file.Size
		totalChunks += int64(len(h.refs))
		for _, r := range h.refs {
			uniq[r.Hash]++
		}
		newCache[h.file.Path] = h.entry
	}

	// Unchanged fast path: file set identical to last push.
	sig := fileSig(out)
	canon, mhash, err := manifest.Canonical()
	if err != nil {
		return nil, err
	}
	if prev.FileSig == sig && prev.LastSnapshot != "" {
		st2 := *prev
		st2.FileCache = newCache
		if err := st.Save(app, slot, &st2); err != nil {
			return nil, err
		}
		return &PushResult{Snapshot: prev.LastSnapshot, Files: int64(len(files)),
			Dirs: int64(len(dirs)), Bytes: mfiles, Chunks: totalChunks,
			Duration: time.Since(t0), Unchanged: true, Skipped: int64(len(skipped)), SkippedFiles: skipped}, nil
	}
	if opt.DryRun {
		return &PushResult{Files: int64(len(files)), Dirs: int64(len(dirs)),
			Bytes: mfiles, Chunks: totalChunks, Deduped: int64(len(uniq)),
			Duration: time.Since(t0), Skipped: int64(len(skipped)), SkippedFiles: skipped}, nil
	}

	// Begin.
	resp, err := c.req(ctx, "POST", fmt.Sprintf("/v1/apps/%s/slots/%s/snapshots", app, slot),
		bytes.NewReader(canon), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	var begin struct {
		ID       string   `json:"id"`
		Missing  []string `json:"missing"`
		ChunkURL string   `json:"chunk_url"`
	}
	if err := c.decode(resp, &begin); err != nil {
		return nil, err
	}
	ev(Event{Kind: EvUpload, Detail: fmt.Sprintf("%d missing", len(begin.Missing))})

	// Upload missing chunks: read them back from local files by hash.
	// Build hash->file map lazily by rechunking once into a temp index.
	need := map[string]bool{}
	for _, h := range begin.Missing {
		need[h] = true
	}
	chunkData := map[string][]byte{}
	for i, f := range files {
		i, f := i, f
		needed := false
		for _, r := range out[i].refs {
			if need[hex.EncodeToString(r.Hash[:])] {
				needed = true
				break
			}
		}
		if !needed {
			continue
		}
		// Re-split the file and collect needed chunks.
		fp, err := f.root.Open(f.rel)
		if err != nil {
			return nil, err
		}
		ch, err := cdc.NewChunker(fp, c.cfg.CDC)
		if err != nil {
			_ = fp.Close()
			return nil, err
		}
		for {
			b, err := ch.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = fp.Close()
				return nil, err
			}
			hh := api.HashBytes(b)
			h := hex.EncodeToString(hh[:])
			if need[h] {
				cp := make([]byte, len(b))
				copy(cp, b)
				chunkData[h] = cp
			}
		}
		_ = fp.Close()
	}
	// Parallel upload.
	var uploaded, uploadedBytes int64
	var mu2 sync.Mutex
	var uerr error
	var wg2 sync.WaitGroup
	sem2 := make(chan struct{}, c.cfg.Concurrency)
	for _, hx := range begin.Missing {
		hx := hx
		b, ok := chunkData[hx]
		if !ok {
			return nil, fmt.Errorf("client: chunk %s missing locally", hx)
		}
		wg2.Add(1)
		sem2 <- struct{}{}
		go func() {
			defer wg2.Done()
			defer func() { <-sem2 }()
			var lastErr error
			for a := 0; a <= c.cfg.Retries; a++ {
				req, err := http.NewRequestWithContext(ctx, "PUT",
					c.cfg.BaseURL+begin.ChunkURL+hx, newLimitReader(bytes.NewReader(b), c.cfg.BandwidthLimit))
				if err != nil {
					lastErr = err
					break
				}
				req.ContentLength = int64(len(b))
				req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
				req.Header.Set("User-Agent", c.agent)
				req.ContentLength = int64(len(b))
				resp, err := c.http.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				if err == nil && (resp.StatusCode == 201 || resp.StatusCode == 200) {
					mu2.Lock()
					uploaded++
					uploadedBytes += int64(len(b))
					mu2.Unlock()
					return
				}
				if err == nil {
					lastErr = fmt.Errorf("chunk put: %d", resp.StatusCode)
					if resp.StatusCode < 500 && resp.StatusCode != 429 {
						break
					}
				} else {
					lastErr = err
				}
				select {
				case <-ctx.Done():
					lastErr = ctx.Err()
					a = c.cfg.Retries
				case <-time.After(backoff(a)):
				}
			}
			if lastErr != nil {
				mu2.Lock()
				if uerr == nil {
					uerr = lastErr
				}
				mu2.Unlock()
			}
		}()
	}
	wg2.Wait()
	if uerr != nil {
		return nil, uerr
	}

	// Commit.
	expected := prev.LastSnapshot
	commitURL := fmt.Sprintf("/v1/apps/%s/slots/%s/snapshots/%s/commit", app, slot, begin.ID)
	if opt.Force {
		commitURL += "?force=1"
	}
	creq, err := c.req(ctx, "POST", commitURL,
		nil, map[string]string{"If-Match": `"` + expected + `"`})
	if err != nil {
		return nil, err
	}
	if creq.StatusCode == 409 {
		var p struct {
			Head json.RawMessage `json:"head"`
		}
		_ = json.NewDecoder(creq.Body).Decode(&p)
		_ = creq.Body.Close()
		var head string
		var s0 string
		if json.Unmarshal(p.Head, &s0) == nil {
			head = s0
		} else {
			var o struct{ ID string }
			_ = json.Unmarshal(p.Head, &o)
			head = o.ID
		}
		return nil, &ConflictError{Head: head}
	}
	if err := c.decode(creq, nil); err != nil {
		return nil, err
	}
	ev(Event{Kind: EvCommit, Detail: begin.ID})
	nst := &State{DeviceID: opt.Device, LastSnapshot: begin.ID,
		LastManifestHash: mhash, FileSig: sig, FileCache: newCache}
	if err := st.Save(app, slot, nst); err != nil {
		return nil, err
	}
	return &PushResult{Snapshot: begin.ID, Files: int64(len(files)),
		Dirs: int64(len(dirs)), Bytes: mfiles, Chunks: totalChunks,
		Uploaded: uploaded, Deduped: totalChunks - uploaded,
		BytesUploaded: uploadedBytes, Duration: time.Since(t0), Skipped: int64(len(skipped)), SkippedFiles: skipped}, nil
}

type hashed struct {
	file  api.File
	refs  []api.ChunkRef
	entry FileEntry
}

// fileSig hashes the manifest file list so label and parent changes
// alone do not create a new snapshot.
func fileSig(hs []hashed) string {
	h := sha256.New()
	for _, e := range hs {
		h.Write([]byte(e.file.Path))
		var sz [8]byte
		binary.LittleEndian.PutUint64(sz[:], uint64(e.file.Size)) // #nosec G115 -- file size non-negative by construction
		h.Write(sz[:])
		for _, r := range e.refs {
			h.Write(r.Hash[:])
		}
		if e.entry.Inline {
			h.Write([]byte{1})
			h.Write(e.entry.InlineHash[:])
		}
		var mode [4]byte
		binary.LittleEndian.PutUint32(mode[:], e.file.Mode)
		h.Write(mode[:])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

var _ = strings.HasPrefix
var _ = errors.Is

// limitReader applies a token-bucket cap of bytesPerSec.
type limitReader struct {
	r    io.Reader
	rate int64
	next time.Time
	mu   sync.Mutex
}

// newLimitReader wraps r with a rough rate limiter.
func newLimitReader(r io.Reader, rate int64) io.Reader {
	return &limitReader{r: r, rate: rate, next: time.Now()}
}

// Read waits until the token bucket allows len(p) bytes.
func (l *limitReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	if n <= 0 || l.rate <= 0 {
		return n, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next = l.next.Add(time.Duration(int64(n) * int64(time.Second) / l.rate))
	d := time.Until(l.next)
	if d > 0 {
		time.Sleep(d)
	}
	return n, err
}
