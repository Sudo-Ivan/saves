// SPDX-License-Identifier: 0BSD

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// ChunkRef points one file segment at a content addressed chunk.
type ChunkRef struct {
	Hash Hash   `json:"h" doc:"SHA-256 of the chunk content"`
	Size uint32 `json:"n" doc:"uncompressed chunk length in bytes"`
}

// File describes one regular file in a snapshot.
type File struct {
	Path      string     `json:"path" doc:"slash separated relative path, see ValidatePath"`
	Size      int64      `json:"size" doc:"total file size in bytes"`
	Mode      uint32     `json:"mode" doc:"permission bits only, masked to 0777"`
	ModTimeNS int64      `json:"mtime_ns" doc:"modification time as Unix nanoseconds"`
	Chunks    []ChunkRef `json:"chunks,omitempty" doc:"ordered content defined chunks"`
	Inline    []byte     `json:"inline,omitempty" doc:"whole file content when small enough, base64 in JSON"`
}

// EncInfo marks an end-to-end encrypted snapshot.
type EncInfo struct {
	V   int    `json:"v" doc:"encryption format version, always 1"`
	Alg string `json:"alg" doc:"cipher suite, e.g. xchacha20poly1305-siv-v1"`
	KID string `json:"kid" doc:"16 hex char key id"`
}

// Manifest is the immutable content listing of one snapshot.
type Manifest struct {
	Version int      `json:"version" doc:"manifest format version, always 1"`
	Enc     *EncInfo `json:"enc,omitempty" doc:"encryption marker for vault snapshots"`
	Parent  string   `json:"parent,omitempty" doc:"previous snapshot id, informational"`
	Device  string   `json:"device,omitempty" doc:"originating device label"`
	Label   string   `json:"label,omitempty" doc:"human readable snapshot label"`
	Dirs    []string `json:"dirs,omitempty" doc:"explicit empty directories"`
	Files   []File   `json:"files" doc:"sorted unique file entries"`
}

// Limits bounds what a manifest may declare.
type Limits struct {
	InlineMaxBytes       int64 `json:"inline_max_bytes" doc:"largest file allowed to carry Inline content"`
	MinChunkBytes        int64 `json:"min_chunk_bytes" doc:"smallest allowed non-final chunk"`
	MaxChunkBytes        int64 `json:"max_chunk_bytes" doc:"largest allowed chunk"`
	MaxFiles             int   `json:"max_files" doc:"max file entries per snapshot"`
	MaxChunksPerSnapshot int   `json:"max_chunks_per_snapshot" doc:"max total chunk refs per snapshot"`
	MaxFileBytes         int64 `json:"max_file_bytes" doc:"largest single file"`
	MaxSnapshotBytes     int64 `json:"max_snapshot_bytes" doc:"largest summed file sizes"`
	MaxManifestBytes     int64 `json:"max_manifest_bytes" doc:"largest encoded manifest"`
	MaxPathDepth         int   `json:"max_path_depth" doc:"deepest allowed path component count"`
}

// DefaultLimits returns the server default manifest limits.
func DefaultLimits() Limits {
	return Limits{
		InlineMaxBytes:       64 << 10,
		MinChunkBytes:        128 << 10,
		MaxChunkBytes:        2 << 20,
		MaxFiles:             1 << 20,
		MaxChunksPerSnapshot: 1 << 22,
		MaxFileBytes:         64 << 30,
		MaxSnapshotBytes:     1 << 40,
		MaxManifestBytes:     64 << 20,
		MaxPathDepth:         64,
	}
}

// Validate checks a decoded manifest against structural rules and lim.
func (m *Manifest) Validate(lim Limits) error {
	if m.Version != 1 {
		return fmt.Errorf("manifest: unsupported version %d", m.Version)
	}
	if m.Enc != nil {
		if err := m.validateEnc(); err != nil {
			return err
		}
	}
	if len(m.Files) > lim.MaxFiles {
		return fmt.Errorf("manifest: %d files exceeds max_files %d", len(m.Files), lim.MaxFiles)
	}
	var totalBytes, totalChunks int64
	var lastPath string
	seenFold := make(map[string]string, len(m.Files))
	dirs := make(map[string]struct{}, len(m.Dirs))
	for _, d := range m.Dirs {
		if err := ValidatePath(d, lim.MaxPathDepth); err != nil {
			return fmt.Errorf("manifest: dir %q: %w", d, err)
		}
		dirs[d] = struct{}{}
	}
	for i := range m.Files {
		f := &m.Files[i]
		if err := ValidatePath(f.Path, lim.MaxPathDepth); err != nil {
			return fmt.Errorf("manifest: file %q: %w", f.Path, err)
		}
		if i > 0 && !(lastPath < f.Path) {
			return fmt.Errorf("manifest: files not sorted or duplicate at %q", f.Path)
		}
		lastPath = f.Path
		fold := strings.ToLower(f.Path)
		if prev, ok := seenFold[fold]; ok {
			return fmt.Errorf("manifest: %q equals %q under case folding", f.Path, prev)
		}
		seenFold[fold] = f.Path
		if _, ok := dirs[f.Path]; ok {
			return fmt.Errorf("manifest: path %q listed as file and dir", f.Path)
		}
		if err := checkNoDirPrefix(f.Path, i, m.Files); err != nil {
			return err
		}
		f.Mode &= 0o777
		if f.Size < 0 {
			return fmt.Errorf("manifest: file %q: negative size", f.Path)
		}
		if f.Size > lim.MaxFileBytes {
			return fmt.Errorf("manifest: file %q: size %d exceeds max_file_bytes %d", f.Path, f.Size, lim.MaxFileBytes)
		}
		totalBytes += f.Size
		if totalBytes > lim.MaxSnapshotBytes {
			return fmt.Errorf("manifest: total size exceeds max_snapshot_bytes %d", lim.MaxSnapshotBytes)
		}
		if err := validateFileBody(f, lim); err != nil {
			return err
		}
		totalChunks += int64(len(f.Chunks))
		if totalChunks > int64(lim.MaxChunksPerSnapshot) {
			return fmt.Errorf("manifest: chunk count exceeds max_chunks_per_snapshot %d", lim.MaxChunksPerSnapshot)
		}
	}
	return nil
}

func checkNoDirPrefix(path string, i int, files []File) error {
	for j := i + 1; j < len(files); j++ {
		p := files[j].Path
		if !strings.HasPrefix(p, path) {
			break
		}
		if len(p) > len(path) && p[len(path)] == '/' {
			return fmt.Errorf("manifest: %q is a directory prefix of %q", path, p)
		}
	}
	return nil
}

// validateEnc enforces the opaque shape of encrypted manifests.
func (m *Manifest) validateEnc() error {
	if m.Enc.V != 1 || (m.Enc.Alg != "xchacha20poly1305-siv-v1") {
		return fmt.Errorf("manifest: enc: bad version or alg")
	}
	if len(m.Enc.KID) != 16 || !isLowerHex(m.Enc.KID) {
		return fmt.Errorf("manifest: enc: bad kid")
	}
	if len(m.Dirs) > 0 {
		return fmt.Errorf("manifest: enc: dirs must be empty")
	}
	metaCount := 0
	for i := range m.Files {
		f := &m.Files[i]
		if f.Path == "meta" {
			metaCount++
		} else if len(f.Path) != 32 || !isLowerHex(f.Path) {
			return fmt.Errorf("manifest: enc: path %q not an opaque id", f.Path)
		}
		if f.Mode != 0o600 || f.ModTimeNS != 0 {
			return fmt.Errorf("manifest: enc: mode/mtime must be zeroed")
		}
	}
	if metaCount != 1 {
		return fmt.Errorf("manifest: enc: exactly one meta file required, got %d", metaCount)
	}
	return nil
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateFileBody(f *File, lim Limits) error {
	n := len(f.Chunks)
	hasInline := f.Inline != nil
	switch {
	case n == 0 && !hasInline:
		if f.Size != 0 {
			return fmt.Errorf("manifest: file %q: no chunks or inline content", f.Path)
		}
		return nil
	case n > 0 && hasInline:
		return fmt.Errorf("manifest: file %q: both chunks and inline set", f.Path)
	case hasInline:
		if f.Size > lim.InlineMaxBytes {
			return fmt.Errorf("manifest: file %q: inline size %d exceeds inline_max_bytes %d", f.Path, f.Size, lim.InlineMaxBytes)
		}
		if int64(len(f.Inline)) != f.Size {
			return fmt.Errorf("manifest: file %q: inline length %d != size %d", f.Path, len(f.Inline), f.Size)
		}
		return nil
	}
	var sum int64
	for i, c := range f.Chunks {
		sum += int64(c.Size)
		if int64(c.Size) > lim.MaxChunkBytes {
			return fmt.Errorf("manifest: file %q: chunk %d size %d exceeds max_chunk_bytes %d", f.Path, i, c.Size, lim.MaxChunkBytes)
		}
		if i < n-1 && int64(c.Size) < lim.MinChunkBytes {
			return fmt.Errorf("manifest: file %q: chunk %d size %d below min_chunk_bytes %d", f.Path, i, c.Size, lim.MinChunkBytes)
		}
	}
	if sum != f.Size {
		return fmt.Errorf("manifest: file %q: chunk sizes %d != size %d", f.Path, sum, f.Size)
	}
	return nil
}

// DecodeManifest strictly decodes a manifest JSON document of at most
// maxBytes. Unknown fields, trailing data, and duplicate keys are rejected.
func DecodeManifest(r io.Reader, maxBytes int64) (*Manifest, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultLimits().MaxManifestBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("manifest: read: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("manifest: exceeds %d bytes", maxBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest: trailing data")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("manifest: trailing data")
	}
	return &m, nil
}

// rejectDuplicateKeys walks the JSON token stream and fails if any object
// contains the same key twice.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return scanValue(dec)
}

func scanValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("manifest: %w", err)
			}
			key, ok := kt.(string)
			if !ok {
				return errors.New("manifest: non-string object key")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("manifest: duplicate key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := scanValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return nil
	}
}

// Canonical returns the deterministic JSON encoding of m and its hash.
// Fields are emitted in declaration order with sorted file and dir lists.
func (m *Manifest) Canonical() ([]byte, Hash, error) {
	c := *m
	c.Files = slices.Clone(m.Files)
	c.Dirs = slices.Clone(m.Dirs)
	slices.SortFunc(c.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	slices.Sort(c.Dirs)
	for i := range c.Files {
		c.Files[i].Mode &= 0o777
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&c); err != nil {
		return nil, Hash{}, fmt.Errorf("manifest: canonical encode: %w", err)
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	return b, Hash(sha256.Sum256(b)), nil
}
