// SPDX-License-Identifier: 0BSD

// Package cdc implements normalized FastCDC content defined chunking.
// Chunk boundaries depend only on content, so identical data chunks the
// same way in memory or through the streaming Chunker.
package cdc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
)

// Params configures the splitter. Sizes are in bytes.
type Params struct {
	Min int `json:"min" doc:"minimum chunk size"`
	Avg int `json:"avg" doc:"target average chunk size, a power of two"`
	Max int `json:"max" doc:"maximum chunk size"`
}

// DefaultParams returns the spec defaults: 128 KiB min, 512 KiB average,
// 2 MiB max.
func DefaultParams() Params {
	return Params{Min: 128 << 10, Avg: 512 << 10, Max: 2 << 20}
}

// Validate checks the parameters.
func (p Params) Validate() error {
	if p.Min < 1<<10 {
		return fmt.Errorf("cdc: min %d too small", p.Min)
	}
	if p.Avg < p.Min || p.Avg > p.Max || p.Avg&(p.Avg-1) != 0 {
		return fmt.Errorf("cdc: avg %d must be a power of two in [min, max]", p.Avg)
	}
	if p.Max > 1<<26 {
		return fmt.Errorf("cdc: max %d too large", p.Max)
	}
	return nil
}

// gearSeed is the fixed seed expanding the gear table with SHA-256.
// The table is deterministic across platforms and Go versions.
const gearSeed = "saves-fastcdc-gear-v1"

var gearTable = buildGear()

func buildGear() (g [256]uint64) {
	var block [32]byte
	counter := sha256.Sum256([]byte(gearSeed))
	for i := range g {
		if i%4 == 0 {
			counter = sha256.Sum256(counter[:])
			block = counter
		}
		g[i] = binary.LittleEndian.Uint64(block[(i%4)*8:])
	}
	return g
}

func masks(avg int) (maskS, maskL uint64) {
	bits := uint(0)
	for v := avg; v > 1; v >>= 1 {
		bits++
	}
	maskS = (1 << (bits + 1)) - 1
	maskL = (1 << (bits - 1)) - 1
	return maskS, maskL
}

// cutPoint scans data[:min(len,max)] for a boundary. It returns the cut
// length and true when a boundary was found. When the region ends without
// a boundary it returns the scanned length and false.
func cutPoint(p Params, data []byte) (int, bool) {
	n := len(data)
	if n <= p.Min {
		return n, false
	}
	if n > p.Max {
		n = p.Max
	}
	maskS, maskL := masks(p.Avg)
	var fp uint64
	i := p.Min
	mid := min(p.Avg, n)
	for ; i < mid; i++ {
		fp = (fp << 1) + gearTable[data[i]]
		if fp&maskS == 0 {
			return i + 1, true
		}
	}
	for ; i < n; i++ {
		fp = (fp << 1) + gearTable[data[i]]
		if fp&maskL == 0 {
			return i + 1, true
		}
	}
	return n, false
}

// Split calls fn for each chunk as a subs slice of data. Returning false
// from fn stops the iteration early.
func Split(p Params, data []byte, fn func(chunk []byte) bool) {
	for len(data) > 0 {
		// cutPoint already returns min(len(data), p.Max) when no
		// boundary exists, so n always bounds the emitted chunk.
		n, _ := cutPoint(p, data)
		if !fn(data[:n]) {
			return
		}
		data = data[n:]
	}
}

// Chunks returns data split into chunk slices sharing the input backing
// array.
func Chunks(p Params, data []byte) [][]byte {
	var out [][]byte
	Split(p, data, func(c []byte) bool {
		out = append(out, c)
		return true
	})
	return out
}

// SplitSeq returns an iterator over chunk slices of data.
func SplitSeq(p Params, data []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		Split(p, data, yield)
	}
}

const ioChunk = 64 << 10

// Chunker chunks an io.Reader stream. Results are identical to splitting
// the full input in memory regardless of the reader's read sizes. The
// rolling fingerprint state persists across fills, so each byte is hashed
// exactly once.
type Chunker struct {
	r      io.Reader
	p      Params
	maskS  uint64
	maskL  uint64
	buf    []byte
	start  int
	end    int
	scan   int
	fp     uint64
	cut    int
	eof    bool
	err    error
	closed bool
}

// NewChunker returns a Chunker reading r with parameters p.
func NewChunker(r io.Reader, p Params) (*Chunker, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	maskS, maskL := masks(p.Avg)
	c := &Chunker{r: r, p: p, maskS: maskS, maskL: maskL, buf: make([]byte, p.Max+ioChunk)}
	c.reset()
	return c, nil
}

func (c *Chunker) reset() {
	c.cut = 0
	c.fp = 0
	c.scan = c.p.Min
}

// Next returns the next chunk, or io.EOF when the stream is done.
// The returned slice aliases the chunker's internal buffer and is valid
// only until the next call to Next.
func (c *Chunker) Next() ([]byte, error) {
	if c.closed {
		return nil, errors.New("cdc: chunker closed")
	}
	for {
		if c.cut == 0 {
			c.scanBuf()
		}
		if c.cut > 0 {
			out := c.buf[c.start : c.start+c.cut]
			c.start += c.cut
			c.reset()
			return out, nil
		}
		if c.eof {
			if c.end > c.start {
				out := c.buf[c.start:c.end]
				c.start = c.end
				return out, nil
			}
			return nil, c.err
		}
		c.fill()
	}
}

// scanBuf advances the boundary scan over buffered data. It hashes each
// byte once and records a pending cut when a boundary or the max chunk
// size is reached.
func (c *Chunker) scanBuf() {
	avail := c.end - c.start
	buf := c.buf[c.start:]
	fp := c.fp
	scan := c.scan
	minB, avg, maxB := c.p.Min, c.p.Avg, c.p.Max
	maskS, maskL := c.maskS, c.maskL
	for scan < avail {
		i := scan
		if i >= maxB {
			c.fp, c.scan, c.cut = fp, scan, maxB
			return
		}
		fp = (fp << 1) + gearTable[buf[i]]
		scan++
		if scan > minB {
			if i < avg {
				if fp&maskS == 0 {
					c.fp, c.scan, c.cut = fp, scan, scan
					return
				}
			} else if fp&maskL == 0 {
				c.fp, c.scan, c.cut = fp, scan, scan
				return
			}
		}
	}
	c.fp, c.scan = fp, scan
}

// fill reads more input into the buffer, compacting consumed bytes.
func (c *Chunker) fill() {
	if c.start > 0 {
		if c.end == c.start {
			c.start, c.end = 0, 0
		} else if c.start >= c.p.Max {
			copy(c.buf, c.buf[c.start:c.end])
			c.end -= c.start
			c.start = 0
		}
	}
	if c.end+ioChunk > cap(c.buf) && c.start > 0 {
		copy(c.buf, c.buf[c.start:c.end])
		c.end -= c.start
		c.start = 0
	}
	n, err := c.r.Read(c.buf[c.end:cap(c.buf)])
	c.end += n
	if err == io.EOF {
		c.eof = true
		c.err = io.EOF
	} else if err != nil {
		c.eof = true
		c.err = err
	}
}

// Each calls fn for every chunk. The slice passed to fn is reused across
// calls; copy it if it must outlive the call.
func (c *Chunker) Each(fn func(chunk []byte) error) error {
	for {
		b, err := c.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(b); err != nil {
			return err
		}
	}
}

// Close releases the buffer and marks the chunker closed.
func (c *Chunker) Close() error {
	c.closed = true
	c.buf = nil
	return nil
}
