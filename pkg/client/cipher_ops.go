// SPDX-License-Identifier: 0BSD

package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Sudo-Ivan/saves/pkg/api"
	"github.com/Sudo-Ivan/saves/pkg/cdc"
)

// encPush builds a sealed manifest: per real file a PathID entry with
// ciphertext refs, plus a "meta" file carrying the sealed plaintext map.
func (c *Client) encPush(ctx context.Context, app, slot string, src Source, st StateStore, opt PushOptions) (*PushResult, error) {
	ev := opt.OnEvent
	if ev == nil {
		ev = func(Event) {}
	}
	t0 := time.Now()
	prev, _ := st.Load(app, slot)
	files, dirs, skipped, err := walkSource(src, DefaultIgnore(), ev)
	if err != nil {
		return nil, err
	}
	type ef struct {
		real string
		f    scanFile
	}
	var sealed []ef
	var manifest api.Manifest
	manifest.Version = 1
	manifest.Device = opt.Device
	manifest.Label = opt.Label
	manifest.Parent = ""
	if prev != nil {
		manifest.Parent = prev.LastSnapshot
	}
	manifest.Enc = &api.EncInfo{V: 1, Alg: "xchacha20poly1305-siv-v1", KID: c.cfg.Cipher.KID()}
	type metaEnt struct {
		Path     string `json:"path"`
		ID       string `json:"id"`
		Size     int64  `json:"size"`
		Mode     uint32 `json:"mode"`
		ModTimeN int64  `json:"mtime_ns"`
		Chunks   int    `json:"chunks"`
	}
	metaBody := struct {
		V     int       `json:"v"`
		Files []metaEnt `json:"files"`
		Dirs  []string  `json:"dirs"`
	}{V: 1, Dirs: dirs}
	var chunkData map[string][]byte
	var needData bool
	var totalChunks, mfiles int64
	var encFiles []api.File
	chunkRefsOf := map[string][]api.ChunkRef{}
	for _, f := range files {
		encFiles = append(encFiles, api.File{})
		sealed = append(sealed, ef{real: f.path, f: f})
	}
	// chunk+seal each file.
	now := time.Now()
	_ = now
	for i := range sealed {
		f := sealed[i].f
		var refs []api.ChunkRef
		var size int64
		// Unchanged fast path: reuse sealed refs from the file cache.
		if prev != nil {
			if e, ok := prev.FileCache[sealed[i].real]; ok &&
				e.Size == f.size && e.ModTimeNS == f.mtimeNS && len(e.Chunks) > 0 {
				encFiles[i] = api.File{Path: c.cfg.Cipher.PathID(sealed[i].real),
					Size: e.SealedSize, Mode: 0o600, Chunks: e.Chunks}
				chunkRefsOf[sealed[i].real] = e.Chunks
				metaBody.Files = append(metaBody.Files, metaEnt{
					Path: sealed[i].real, ID: encFiles[i].Path, Size: f.size,
					Mode: f.mode, ModTimeN: f.mtimeNS, Chunks: len(e.Chunks)})
				mfiles += e.SealedSize
				continue
			}
		}
		inl, _ := f.root.Lstat(f.rel)
		if inl != nil && inl.Size() <= int64(64<<10) {
			b, err := os.ReadFile(filepath.Join(f.rel))
			_ = b
			_ = err
		}
		fp, err := f.root.Open(f.rel)
		if err != nil {
			return nil, err
		}
		fi, _ := fp.Stat()
		if fi != nil && fi.Size() <= 64<<10 {
			b, _ := io.ReadAll(fp)
			fp.Close()
			ct := c.cfg.Cipher.SealInline(b)
			size = int64(len(ct))
			encFiles[i] = api.File{Path: c.cfg.Cipher.PathID(sealed[i].real),
				Size: size, Mode: 0o600, Inline: ct}
			metaBody.Files = append(metaBody.Files, metaEnt{
				Path: sealed[i].real, ID: encFiles[i].Path, Size: int64(len(b)),
				Mode: f.mode, ModTimeN: f.mtimeNS, Chunks: 0})
			mfiles += size
			continue
		}
		ch, err := cdc.NewChunker(fp, c.cfg.CDC)
		if err != nil {
			fp.Close()
			return nil, err
		}
		for {
			b, err := ch.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				fp.Close()
				return nil, err
			}
			ct := c.cfg.Cipher.SealChunk(b)
			h := api.HashBytes(ct)
			refs = append(refs, api.ChunkRef{Hash: h, Size: uint32(len(ct))})
			size += int64(len(ct))
			totalChunks++
			if chunkData == nil {
				chunkData = map[string][]byte{}
			}
			if needData || true {
				chunkData[hex.EncodeToString(h[:])] = ct
			}
		}
		fp.Close()
		encFiles[i] = api.File{Path: c.cfg.Cipher.PathID(sealed[i].real),
			Size: size, Mode: 0o600, Chunks: refs}
		chunkRefsOf[sealed[i].real] = refs
		metaBody.Files = append(metaBody.Files, metaEnt{
			Path: sealed[i].real, ID: encFiles[i].Path, Size: f.size,
			Mode: f.mode, ModTimeN: f.mtimeNS, Chunks: len(refs)})
		mfiles += size
	}
	// Deterministic content signature over the plaintext tree.
	sh := sha256.New()
	for i := range sealed {
		sh.Write([]byte(sealed[i].real))
		binary.Write(sh, binary.LittleEndian, sealed[i].f.size)
		binary.Write(sh, binary.LittleEndian, int64(sealed[i].f.mode))
		binary.Write(sh, binary.LittleEndian, sealed[i].f.mtimeNS)
		for _, r := range chunkRefsOf[sealed[i].real] {
			sh.Write(r.Hash[:])
			binary.Write(sh, binary.LittleEndian, int64(r.Size))
		}
	}
	for _, d := range dirs {
		sh.Write([]byte(d))
	}
	sig := hex.EncodeToString(sh.Sum(nil))
	if prev != nil && prev.ContentSig == sig && prev.LastSnapshot != "" {
		return &PushResult{Snapshot: prev.LastSnapshot, Files: int64(len(files)),
			Dirs: int64(len(dirs)), Bytes: mfiles, Chunks: totalChunks,
			Duration: time.Since(t0), Unchanged: true, Skipped: skipped}, nil
	}
	// meta entry (only generated when something changed).
	mj, _ := json.Marshal(metaBody)
	mct := c.cfg.Cipher.SealMeta(mj)
	me := api.File{Path: "meta", Size: int64(len(mct)), Mode: 0o600}
	if len(mct) <= int(64<<10) {
		me.Inline = mct
	} else {
		for len(mct) > 0 {
			n := len(mct)
			if n > int(c.cfg.CDC.Max) {
				n = int(c.cfg.CDC.Max)
			}
			part := mct[:n]
			mct = mct[n:]
			h := api.HashBytes(part)
			me.Chunks = append(me.Chunks, api.ChunkRef{Hash: h, Size: uint32(len(part))})
			chunkData[hex.EncodeToString(h[:])] = part
			totalChunks++
		}
	}
	manifest.Files = append(encFiles, me)
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	canon, mhash, err := manifest.Canonical()
	if err != nil {
		return nil, err
	}
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
	var uploaded, uploadedBytes int64
	for _, hx := range begin.Missing {
		b, ok := chunkData[hx]
		if !ok {
			return nil, fmt.Errorf("client: sealed chunk %s missing", hx)
		}
		req, err := c.req(ctx, "PUT", begin.ChunkURL+hx, bytes.NewReader(b), nil)
		if err != nil {
			return nil, err
		}
		if err := c.decode(req, nil); err != nil {
			return nil, err
		}
		uploaded++
		uploadedBytes += int64(len(b))
	}
	expected := ""
	if prev != nil {
		expected = prev.LastSnapshot
	}
	cu := fmt.Sprintf("/v1/apps/%s/slots/%s/snapshots/%s/commit", app, slot, begin.ID)
	if opt.Force {
		cu += "?force=1"
	}
	cmt, err := c.req(ctx, "POST", cu, nil,
		map[string]string{"If-Match": `"` + expected + `"`})
	if err != nil {
		return nil, err
	}
	if err := c.decode(cmt, nil); err != nil {
		return nil, err
	}
	var st2 State
	if prev != nil {
		st2 = *prev
	}
	st2.LastManifestHash = mhash
	st2.ContentSig = sig
	st2.LastSnapshot = begin.ID
	st2.FileCache = map[string]FileEntry{}
	for i := range sealed {
		st2.FileCache[sealed[i].real] = FileEntry{
			Size: sealed[i].f.size, ModTimeNS: sealed[i].f.mtimeNS,
			Mode: sealed[i].f.mode, Chunks: chunkRefsOf[sealed[i].real],
			Inline: len(chunkRefsOf[sealed[i].real]) == 0,
		}
	}
	if err := st.Save(app, slot, &st2); err != nil {
		return nil, err
	}
	return &PushResult{Snapshot: begin.ID, Files: int64(len(files)),
		Dirs: int64(len(dirs)), Bytes: mfiles, Chunks: totalChunks,
		Uploaded: uploaded, BytesUploaded: uploadedBytes,
		Duration: time.Since(t0), Skipped: skipped}, nil
}

// encPull decrypts an encrypted snapshot.
func (c *Client) encPull(ctx context.Context, app, slot, snapshot string, m *api.Manifest, src Source, st StateStore, opt PullOptions) (*PullResult, error) {
	if c.cfg.Cipher == nil {
		return nil, &EncryptedError{Hint: "no vault key configured"}
	}
	if m.Enc == nil || m.Enc.KID != c.cfg.Cipher.KID() {
		return nil, &KeyMismatchError{Want: c.cfg.Cipher.KID(), Have: ""}
	}
	var metaf *api.File
	for i := range m.Files {
		if m.Files[i].Path == "meta" {
			metaf = &m.Files[i]
		}
	}
	if metaf == nil {
		return nil, ErrBadInput
	}
	var mct []byte
	if metaf.Inline != nil {
		mct = metaf.Inline
	} else {
		for _, r := range metaf.Chunks {
			b, err := c.chunk(ctx, app, r.Hash)
			if err != nil {
				return nil, err
			}
			mct = append(mct, b[:r.Size]...)
		}
	}
	mj, err := c.cfg.Cipher.OpenMeta(mct)
	if err != nil {
		return nil, ErrBadInput
	}
	var metaBody struct {
		V     int `json:"v"`
		Files []struct {
			Path     string `json:"path"`
			ID       string `json:"id"`
			Size     int64  `json:"size"`
			Mode     uint32 `json:"mode"`
			ModTimeN int64  `json:"mtime_ns"`
			Chunks   int    `json:"chunks"`
		} `json:"files"`
		Dirs []string `json:"dirs"`
	}
	if err := json.Unmarshal(mj, &metaBody); err != nil {
		return nil, ErrBadInput
	}
	// map id -> manifest file
	byID := map[string]*api.File{}
	for i := range m.Files {
		byID[m.Files[i].Path] = &m.Files[i]
	}
	res := &PullResult{}
	for _, me := range metaBody.Files {
		dst := byID[me.ID]
		if dst == nil {
			continue
		}
		rt, rel, ok := src.resolve(me.Path)
		if !ok {
			continue
		}
		root, err := rootFor(src, rt.Key)
		if err != nil || root == nil {
			continue
		}
		var plain []byte
		if dst.Inline != nil {
			b, err := c.cfg.Cipher.OpenInline(dst.Inline)
			if err != nil {
				return nil, err
			}
			plain = b
		} else {
			for _, r := range dst.Chunks {
				b, err := c.chunk(ctx, app, r.Hash)
				if err != nil {
					return nil, err
				}
				p2, err := c.cfg.Cipher.OpenChunk(b[:r.Size])
				if err != nil {
					return nil, err
				}
				plain = append(plain, p2...)
			}
		}
		tf, err := root.Create(rel + ".saves-tmp")
		if err != nil {
			return nil, err
		}
		if _, err := tf.Write(plain); err != nil {
			tf.Close()
			return nil, err
		}
		tf.Close()
		if err := root.Rename(rel+".saves-tmp", rel); err != nil {
			return nil, err
		}
		res.Written++
		res.Bytes += me.Size
	}
	for _, d := range metaBody.Dirs {
		rt, rel, ok := src.resolve(d)
		if !ok {
			continue
		}
		if r2, err := rootFor(src, rt.Key); err == nil && r2 != nil {
			_ = r2.MkdirAll(rel, 0o700)
			r2.Close()
		}
	}
	var st2 State
	st2.LastSnapshot = snapshot
	st.Save(app, slot, &st2)
	return res, nil
}

var ErrBadInput = fmt.Errorf("client: bad sealed input")

// rootFor opens the root dir for a key.
func rootFor(src Source, key string) (*os.Root, error) {
	for _, r := range src.Roots {
		if r.Key == key {
			return os.OpenRoot(r.Dir)
		}
	}
	return nil, nil
}
