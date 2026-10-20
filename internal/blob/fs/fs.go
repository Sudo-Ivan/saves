// SPDX-License-Identifier: 0BSD

// Package fs implements blob.Store on a local filesystem rooted at a
// fixed directory. All path access goes through os.Root, so symlinks
// and traversal cannot escape the root. Blobs live at
// u/<uid>/<kind>/<hex[0:2]>/<hex[2:4]>/<hex> giving a two level hex
// fanout. Writes go to a uniquely named file under tmp/ inside the root
// and are renamed into place only after checksum and size verification.
package fs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/config"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// staleTempAge is the age after which files in tmp/ are reclaimed.
const staleTempAge = time.Hour

// Options configures a filesystem store.
type Options struct {
	// Root is the data directory, created with mode 0700 when absent.
	Root string
	// Fsync selects the durability policy: always fsyncs the file and
	// its parent directory, dir fsyncs only the parent directory after
	// rename, never skips syncing.
	Fsync string
}

// OptionsFromConfig maps the config storage.blob.fs section.
func OptionsFromConfig(fc config.FSConfig) Options {
	return Options{Root: fc.Root, Fsync: fc.Fsync}
}

// Store is a filesystem blob store.
type Store struct {
	root *os.Root
	opt  Options
}

var _ blob.Store = (*Store)(nil)

// New opens or creates the store at opt.Root and cleans stale temp files.
func New(opt Options) (*Store, error) {
	if opt.Root == "" {
		return nil, errors.New("blobfs: root is required")
	}
	switch opt.Fsync {
	case "", "always", "dir", "never":
	default:
		return nil, fmt.Errorf("blobfs: fsync %q invalid", opt.Fsync)
	}
	if opt.Fsync == "" {
		opt.Fsync = "dir"
	}
	if err := os.MkdirAll(opt.Root, 0o700); err != nil {
		return nil, fmt.Errorf("blobfs: %w", err)
	}
	if err := os.Chmod(opt.Root, 0o700); err != nil { // #nosec G302 -- data root is a directory, 0700 is intended
		return nil, fmt.Errorf("blobfs: %w", err)
	}
	root, err := os.OpenRoot(opt.Root)
	if err != nil {
		return nil, fmt.Errorf("blobfs: %w", err)
	}
	if err := root.MkdirAll("tmp", 0o700); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("blobfs: %w", err)
	}
	s := &Store{root: root, opt: opt}
	s.cleanTemps()
	return s, nil
}

// path maps a key to its fanout path inside the root.
func storePath(key string) string {
	parts := strings.Split(key, "/")
	h := parts[3]
	return "u/" + parts[1] + "/" + parts[2] + "/" + h[:2] + "/" + h[2:4] + "/" + h
}

// keyFromPath inverts path, reporting false for non-blob paths.
func keyFromPath(p string) (string, bool) {
	parts := strings.Split(p, "/")
	if len(parts) != 6 || parts[0] != "u" {
		return "", false
	}
	key := parts[0] + "/" + parts[1] + "/" + parts[2] + "/" + parts[5]
	if blob.ValidKey(key) != nil {
		return "", false
	}
	return key, true
}

// Put implements blob.Store.Put.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64, want *api.Hash) error {
	if err := blob.ValidKey(key); err != nil {
		return err
	}
	if size < 0 {
		return blob.ErrSizeMismatch
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tmpName, tmp, err := s.newTemp()
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = tmp.Close()
		_ = s.root.Remove(tmpName)
		return err
	}
	h := sha256.New()
	n, err := io.Copy(tmp, io.TeeReader(&ctxReader{ctx: ctx, r: io.LimitReader(r, size+1)}, h))
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if n != size {
		return fail(blob.ErrSizeMismatch)
	}
	if want != nil {
		var sum api.Hash
		copy(sum[:], h.Sum(nil))
		if sum != *want {
			return fail(blob.ErrChecksum)
		}
	}
	dst := storePath(key)
	if _, err := s.root.Stat(dst); err == nil {
		return fail(nil)
	}
	if s.opt.Fsync == "always" {
		if err := tmp.Sync(); err != nil {
			return fail(fmt.Errorf("blobfs: fsync: %w", err))
		}
	}
	if err := tmp.Close(); err != nil {
		_ = s.root.Remove(tmpName)
		return fmt.Errorf("blobfs: %w", err)
	}
	dir := pathDir(dst)
	if err := s.root.MkdirAll(dir, 0o700); err != nil {
		_ = s.root.Remove(tmpName)
		return fmt.Errorf("blobfs: %w", err)
	}
	if err := s.root.Rename(tmpName, dst); err != nil {
		_ = s.root.Remove(tmpName)
		return fmt.Errorf("blobfs: %w", err)
	}
	if s.opt.Fsync == "always" || s.opt.Fsync == "dir" {
		s.syncDir(dir)
	}
	return nil
}

func pathDir(p string) string { return path.Dir(p) }

func (s *Store) syncDir(dir string) {
	d, err := s.root.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

func (s *Store) newTemp() (string, *os.File, error) {
	for tries := 0; tries < 10; tries++ {
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return "", nil, fmt.Errorf("blobfs: %w", err)
		}
		name := "tmp/" + hex.EncodeToString(rnd[:])
		f, err := s.root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("blobfs: temp: %w", err)
		}
		return name, f, nil
	}
	return "", nil, errors.New("blobfs: cannot create unique temp file")
}

// ctxReader aborts reads once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// fileObject adapts *os.File to blob.Object plus FileObject.
type fileObject struct {
	f    *os.File
	size int64
}

func (o *fileObject) ReadAt(p []byte, off int64) (int, error) { return o.f.ReadAt(p, off) }
func (o *fileObject) Close() error                            { return o.f.Close() }
func (o *fileObject) Size() int64                             { return o.size }
func (o *fileObject) File() *os.File                          { return o.f }

// Open implements blob.Store.Open.
func (s *Store) Open(ctx context.Context, key string) (blob.Object, error) {
	if err := blob.ValidKey(key); err != nil {
		return nil, err
	}
	f, err := s.root.Open(storePath(key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, blob.ErrNotFound
		}
		return nil, fmt.Errorf("blobfs: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("blobfs: %w", err)
	}
	return &fileObject{f: f, size: fi.Size()}, nil
}

// Stat implements blob.Store.Stat.
func (s *Store) Stat(ctx context.Context, key string) (int64, error) {
	if err := blob.ValidKey(key); err != nil {
		return 0, err
	}
	fi, err := s.root.Stat(storePath(key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, blob.ErrNotFound
		}
		return 0, fmt.Errorf("blobfs: %w", err)
	}
	return fi.Size(), nil
}

// Delete implements blob.Store.Delete.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := blob.ValidKey(key); err != nil {
		return err
	}
	err := s.root.Remove(storePath(key))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("blobfs: %w", err)
	}
	return nil
}

// List implements blob.Store.List.
func (s *Store) List(ctx context.Context, prefix string, fn func(blob.Entry) error) error {
	var entries []blob.Entry
	err := fs.WalkDir(s.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p == "tmp" || strings.HasPrefix(p, "tmp/") {
				return fs.SkipDir
			}
			return nil
		}
		key, ok := keyFromPath(p)
		if !ok || !strings.HasPrefix(key, prefix) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		entries = append(entries, blob.Entry{Key: key, Size: fi.Size(), ModTime: fi.ModTime()})
		return nil
	})
	if err != nil {
		return err
	}
	slices.SortFunc(entries, func(a, b blob.Entry) int { return strings.Compare(a.Key, b.Key) })
	for _, e := range entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the root.
func (s *Store) Close() error { return s.root.Close() }

// cleanTemps removes stale files under tmp/.
func (s *Store) cleanTemps() {
	d, err := s.root.Open("tmp")
	if err != nil {
		return
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleTempAge)
	for _, name := range names {
		fi, err := s.root.Stat("tmp/" + name)
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			_ = s.root.Remove("tmp/" + name)
		}
	}
}
