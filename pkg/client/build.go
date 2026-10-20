// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
	"github.com/Sudo-Ivan/saves/pkg/cdc"
)

// ChunkLocator maps a chunk hash to where its plaintext lives.
type ChunkLocator map[string]ChunkLoc

// ChunkLoc locates chunk plaintext for peer serving.
type ChunkLoc struct {
	Root   string `json:"root"`
	Rel    string `json:"rel"`
	Offset int64  `json:"off"`
	Len    int64  `json:"len"`
	Sealed bool   `json:"sealed"`
	Meta   bool   `json:"meta,omitempty"`
}

// BuildManifest scans and hashes exactly like Push but does no network.
// It returns the manifest plus a locator for serving chunks to peers.
func (c *Client) BuildManifest(ctx context.Context, app, slot string, src Source, st StateStore, opt PushOptions) (*api.Manifest, *ChunkLocator, error) {
	if c.cfg.Cipher != nil {
		return c.buildManifestEnc(ctx, app, slot, src, st, opt)
	}
	files, dirs, _, err := walkSource(src, DefaultIgnore(), func(Event) {})
	if err != nil {
		return nil, nil, err
	}
	prev, _ := st.Load(app, slot)
	var m api.Manifest
	m.Version = 1
	m.Device = opt.Device
	m.Label = opt.Label
	if prev != nil {
		m.Parent = prev.LastSnapshot
	}
	m.Dirs = dirs
	loc := ChunkLocator{}
	now := time.Now()
	for _, f := range files {
		var refs []api.ChunkRef
		var inl []byte
		if prev != nil {
			if e, ok := prev.FileCache[f.path]; ok && fresh(e, f, now) && !e.Inline {
				refs = e.Chunks
			}
		}
		if refs == nil {
			var err2 error
			var af api.File
			af, refs, inl, err2 = c.chunkFile(ctx, f, int64(64<<10))
			if err2 != nil {
				return nil, nil, err2
			}
			_ = af
		}
		m.Files = append(m.Files, api.File{Path: f.path, Size: f.size,
			Mode: f.mode, ModTimeNS: f.mtimeNS, Chunks: refs, Inline: inl})
		var off int64
		for _, r := range refs {
			loc[hex.EncodeToString(r.Hash[:])] = ChunkLoc{Root: rootKey(f.path),
				Rel: f.rel, Offset: off, Len: int64(r.Size)}
			off += int64(r.Size)
		}
	}
	return &m, &loc, nil
}

// buildManifestEnc seals like encPush but without begin/upload/commit.
func (c *Client) buildManifestEnc(ctx context.Context, app, slot string, src Source, st StateStore, opt PushOptions) (*api.Manifest, *ChunkLocator, error) {
	files, dirs, _, err := walkSource(src, DefaultIgnore(), func(Event) {})
	if err != nil {
		return nil, nil, err
	}
	prev, _ := st.Load(app, slot)
	var m api.Manifest
	m.Version = 1
	m.Device = opt.Device
	m.Label = opt.Label
	if prev != nil {
		m.Parent = prev.LastSnapshot
	}
	m.Enc = &api.EncInfo{V: 1, Alg: "xchacha20poly1305-siv-v1", KID: c.cfg.Cipher.KID()}
	loc := ChunkLocator{}
	type metaEnt struct {
		Path string `json:"path"`
		ID   string `json:"id"`
		Size int64  `json:"size"`
	}
	var metaBody struct {
		V     int       `json:"v"`
		Files []metaEnt `json:"files"`
		Dirs  []string  `json:"dirs"`
	}
	metaBody.V, metaBody.Dirs = 1, dirs
	var enc []api.File
	for _, f := range files {
		var refs []api.ChunkRef
		var size int64
		var plain []byte
		fp, err := f.root.Open(f.rel)
		if err != nil {
			return nil, nil, err
		}
		plain, _ = io.ReadAll(fp)
		fp.Close()
		if len(plain) <= 64<<10 {
			ct := c.cfg.Cipher.SealInline(plain)
			enc = append(enc, api.File{Path: c.cfg.Cipher.PathID(f.path),
				Size: int64(len(ct)), Mode: 0o600, Inline: ct})
		} else {
			ch, err := cdc.NewChunker(bytes.NewReader(plain), c.cfg.CDC)
			if err != nil {
				return nil, nil, err
			}
			var off int64
			for {
				b, err := ch.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, nil, err
				}
				ct := c.cfg.Cipher.SealChunk(b)
				h := api.HashBytes(ct)
				refs = append(refs, api.ChunkRef{Hash: h, Size: uint32(len(ct))})
				loc[hex.EncodeToString(h[:])] = ChunkLoc{Root: rootKey(f.path), Rel: f.rel,
					Offset: off, Len: int64(len(b)), Sealed: true}
				off += int64(len(b))
				size += int64(len(ct))
			}
			enc = append(enc, api.File{Path: c.cfg.Cipher.PathID(f.path),
				Size: size, Mode: 0o600, Chunks: refs})
		}
		metaBody.Files = append(metaBody.Files, metaEnt{
			Path: f.path, ID: c.cfg.Cipher.PathID(f.path), Size: int64(len(plain))})
	}
	mj, _ := json.Marshal(metaBody)
	mct := c.cfg.Cipher.SealMeta(mj)
	me := api.File{Path: "meta", Size: int64(len(mct)), Mode: 0o600}
	if len(mct) <= 64<<10 {
		me.Inline = mct
	} else {
		for len(mct) > 0 {
			n := min(len(mct), c.cfg.CDC.Max)
			part := mct[:n]
			mct = mct[n:]
			h := api.HashBytes(part)
			me.Chunks = append(me.Chunks, api.ChunkRef{Hash: h, Size: uint32(len(part))})
			loc[hex.EncodeToString(h[:])] = ChunkLoc{Meta: true, Len: int64(len(part))}
		}
	}
	m.Files = append(enc, me)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return &m, &loc, nil
}

// rootKey extracts the root key from a manifest path.
func rootKey(mpath string) string {
	if i := strings.IndexByte(mpath, '/'); i > 0 {
		return mpath[:i]
	}
	return mpath
}
