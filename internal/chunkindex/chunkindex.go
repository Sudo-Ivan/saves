// SPDX-License-Identifier: 0BSD

// Package chunkindex exposes a []api.ChunkRef file as an io.ReadSeeker
// backed by lazily opened blob objects. One object is open at a time.
package chunkindex

import (
	"errors"
	"io"
	"sort"
	"sync"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Opener resolves a chunk hash to a blob object.
type Opener func(h api.Hash) (blob.Object, error)

// Reader is an io.ReadSeeker over chunked file content.
type Reader struct {
	refs    []api.ChunkRef
	offsets []int64 // cumulative end offsets
	size    int64
	open    Opener
	pos     int64
	mu      sync.Mutex
	cur     blob.Object
	curIdx  int
	curOff  int64 // object start offset in file
}

// New builds a Reader. refs must cover a contiguous file of size total.
func New(refs []api.ChunkRef, total int64, open Opener) (*Reader, error) {
	if total < 0 {
		return nil, errors.New("chunkindex: negative size")
	}
	r := &Reader{refs: refs, open: open, curIdx: -1}
	var off int64
	for _, c := range refs {
		off += int64(c.Size)
		r.offsets = append(r.offsets, off)
	}
	if off != total {
		return nil, errors.New("chunkindex: chunk sizes do not match total")
	}
	r.size = total
	return r, nil
}

// Size returns the file length.
func (r *Reader) Size() int64 { return r.size }

// chunkAt returns the chunk index and its file offset for position off.
func (r *Reader) chunkAt(off int64) (int, int64) {
	i := sort.Search(len(r.offsets), func(i int) bool { return r.offsets[i] > off })
	start := int64(0)
	if i > 0 {
		start = r.offsets[i-1]
	}
	return i, start
}

func (r *Reader) get(idx int) (blob.Object, error) {
	if r.curIdx == idx && r.cur != nil {
		return r.cur, nil
	}
	if r.cur != nil {
		_ = r.cur.Close()
		r.cur = nil
		r.curIdx = -1
	}
	o, err := r.open(r.refs[idx].Hash)
	if err != nil {
		return nil, err
	}
	r.cur = o
	r.curIdx = idx
	r.curOff = 0
	if idx > 0 {
		r.curOff = r.offsets[idx-1]
	}
	return o, nil
}

// ReadAt reads len(p) bytes at off.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if off < 0 {
		return 0, errors.New("chunkindex: negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) {
		idx, start := r.chunkAt(off)
		if idx >= len(r.refs) {
			break
		}
		o, err := r.get(idx)
		if err != nil {
			return n, err
		}
		want := int64(len(p) - n)
		avail := r.offsets[idx] - off
		if want > avail {
			want = avail
		}
		m, err := o.ReadAt(p[n:n+int(want)], off-start)
		n += m
		off += int64(m)
		if err != nil {
			if err == io.EOF && n == len(p) {
				return n, nil
			}
			return n, err
		}
		if m == 0 {
			break
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Read implements io.Reader over the seek position.
func (r *Reader) Read(p []byte) (int, error) {
	n, err := r.ReadAt(p, r.pos)
	r.pos += int64(n)
	if err == io.EOF && n > 0 {
		return n, nil
	}
	return n, err
}

// Seek implements io.Seeker.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("chunkindex: bad whence")
	}
	if abs < 0 {
		return 0, errors.New("chunkindex: negative position")
	}
	r.pos = abs
	return abs, nil
}

// Close releases the open object.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		r.curIdx = -1
		return err
	}
	return nil
}
