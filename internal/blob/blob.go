// SPDX-License-Identifier: 0BSD

// Package blob defines the content addressed blob store interface used
// for chunks and manifests, plus the key grammar shared by all backends.
package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Store is a content addressed object store scoped to keys produced by
// ChunkKey and ManifestKey.
type Store interface {
	// Put writes size bytes from r under key. When want is non-nil the
	// content SHA-256 is verified while streaming and ErrChecksum is
	// returned on mismatch. ErrSizeMismatch is returned when the stream
	// length differs from size. The publish is atomic. Rewriting an
	// existing key with identical content is not an error.
	Put(ctx context.Context, key string, r io.Reader, size int64, want *api.Hash) error
	// Open returns the object stored under key or ErrNotFound.
	Open(ctx context.Context, key string) (Object, error)
	// Stat returns the object size or ErrNotFound.
	Stat(ctx context.Context, key string) (int64, error)
	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error
	// List calls fn for every key starting with prefix, in key order.
	// Returning an error from fn stops the walk.
	List(ctx context.Context, prefix string, fn func(Entry) error) error
	// Close releases store resources.
	Close() error
}

// Object is a readable blob. ReadAt follows io.ReaderAt semantics.
type Object interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

// FileObject is an optional interface Objects backed by a local file
// implement so net/http can use sendfile via io.Copy.
type FileObject interface {
	File() *os.File
}

// Entry describes one object in a List walk.
type Entry struct {
	Key     string
	Size    int64
	ModTime time.Time
}

var (
	// ErrNotFound is returned when a key does not exist.
	ErrNotFound = errors.New("blob: not found")
	// ErrInvalidKey is returned for keys outside the key grammar.
	ErrInvalidKey = errors.New("blob: invalid key")
	// ErrChecksum is returned when streamed content fails SHA-256 check.
	ErrChecksum = errors.New("blob: checksum mismatch")
	// ErrSizeMismatch is returned when the stream length differs from
	// the declared size.
	ErrSizeMismatch = errors.New("blob: size mismatch")
)

const (
	uidMaxLen = 64
	maxKeyLen = 256
	hexLen    = 64
)

// ChunkKey returns the storage key for user chunk h.
func ChunkKey(uid string, h api.Hash) string {
	return "u/" + uid + "/c/" + h.String()
}

// ManifestKey returns the storage key for user manifest h.
func ManifestKey(uid string, h api.Hash) string {
	return "u/" + uid + "/m/" + h.String()
}

// ValidKey enforces the key grammar:
// u/<userid>/<c|m>/<64 lowercase hex> where userid is 1 to 64 characters
// of [a-zA-Z0-9_-].
func ValidKey(key string) error {
	if len(key) == 0 || len(key) > maxKeyLen {
		return fmt.Errorf("%w: length %d", ErrInvalidKey, len(key))
	}
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "u" {
		return fmt.Errorf("%w: want u/<uid>/<c|m>/<hex>", ErrInvalidKey)
	}
	uid := parts[1]
	if len(uid) == 0 || len(uid) > uidMaxLen {
		return fmt.Errorf("%w: uid length %d", ErrInvalidKey, len(uid))
	}
	for i := 0; i < len(uid); i++ {
		c := uid[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return fmt.Errorf("%w: uid char %q", ErrInvalidKey, c)
		}
	}
	if parts[2] != "c" && parts[2] != "m" {
		return fmt.Errorf("%w: kind %q", ErrInvalidKey, parts[2])
	}
	h := parts[3]
	if len(h) != hexLen {
		return fmt.Errorf("%w: hash length %d", ErrInvalidKey, len(h))
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%w: hash char %q", ErrInvalidKey, c)
		}
	}
	return nil
}
