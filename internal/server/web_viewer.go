// SPDX-License-Identifier: 0BSD

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Sudo-Ivan/saves/internal/detect"
	"github.com/Sudo-Ivan/saves/pkg/api"
)

const (
	viewTextMax = 256 << 10
	viewHexPage = 1024
	diffMaxLine = 2500
)

// treeNode is one entry of the snapshot file tree.
type treeNode struct {
	Name     string
	Href     string
	Dir      bool
	Size     int64
	Files    int
	ModTime  string
	Children []*treeNode
	Open     bool
}

func escSegs(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func buildTree(files []api.File, viewBase string) *treeNode {
	root := &treeNode{Dir: true}
	for _, f := range files {
		cur := root
		segs := strings.Split(f.Path, "/")
		for i, seg := range segs {
			cur.Size += f.Size
			cur.Files++
			last := i == len(segs)-1
			var next *treeNode
			for _, c := range cur.Children {
				if c.Name == seg && c.Dir == !last {
					next = c
					break
				}
			}
			if next == nil {
				next = &treeNode{Name: seg, Dir: !last}
				cur.Children = append(cur.Children, next)
			}
			cur = next
			if last {
				cur.Size = f.Size
				cur.Files = 1
				cur.Href = viewBase + escSegs(f.Path)
				cur.ModTime = time.Unix(0, f.ModTimeNS).UTC().Format("2006-01-02 15:04")
			}
		}
	}
	var sortRec func(n *treeNode)
	sortRec = func(n *treeNode) {
		sort.SliceStable(n.Children, func(i, j int) bool {
			a, b := n.Children[i], n.Children[j]
			if a.Dir != b.Dir {
				return a.Dir
			}
			return a.Name < b.Name
		})
		for _, c := range n.Children {
			sortRec(c)
		}
	}
	sortRec(root)
	var openRec func(n *treeNode, depth int)
	openRec = func(n *treeNode, depth int) {
		for _, c := range n.Children {
			if c.Dir {
				c.Open = depth == 0 || c.Files <= 12
				openRec(c, depth+1)
			}
		}
	}
	openRec(root, 0)
	return root
}

type snapRef struct {
	ID, Label, Device, At string
	Selected              bool
}

type snapshotView struct {
	App, Slot, ID          string
	Back                   string
	Tree                   *treeNode
	Files                  int
	Total                  int64
	Device, Label, Created string
	Encrypted              bool
	Others                 []snapRef
	Base                   string
}

func (wv *webReq) snapLinks(app, slot, id string) (base string) {
	return wv.web.link + "account/apps/" + url.PathEscape(app) + "/slots/" + url.PathEscape(slot) + "/snapshots/" + url.PathEscape(id)
}

func (s *Server) loadManifest(wv *webReq, app, slot, id string) (*api.Manifest, bool) {
	b, _, err := s.Svc.GetManifest(wv.r.Context(), wv.principal(), app, slot, id)
	if err != nil {
		s.webServiceError(wv, err)
		return nil, false
	}
	m, err := api.DecodeManifest(bytes.NewReader(b), int64(len(b))+1)
	if err != nil {
		wv.errorPage(500)
		return nil, false
	}
	return m, true
}

func (s *Server) whSnapshot(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app, slot, id := r.PathValue("app"), r.PathValue("slot"), r.PathValue("id")
	m, ok := s.loadManifest(wv, app, slot, id)
	if !ok {
		return
	}
	base := wv.snapLinks(app, slot, id)
	v := snapshotView{App: app, Slot: slot, ID: id, Device: m.Device, Label: m.Label, Base: base,
		Back: wv.web.link + "account/apps/" + url.PathEscape(app) + "/slots/" + url.PathEscape(slot), Encrypted: m.Enc != nil}
	if !v.Encrypted {
		v.Tree = buildTree(m.Files, base+"/view/")
		v.Files = len(m.Files)
		v.Total = v.Tree.Size
	}
	if sn, _, err := s.Svc.ListSnapshots(r.Context(), wv.principal(), app, slot, "", 50); err == nil {
		for _, x := range sn {
			if x.ID == id {
				v.Created = x.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")
				continue
			}
			v.Others = append(v.Others, snapRef{ID: x.ID, Label: x.Label, Device: x.Device, At: x.CreatedAt.UTC().Format("2006-01-02 15:04")})
		}
	}
	wv.render("snapshot", 200, v)
}

type hexRow struct{ Off, Hex, ASCII string }

type fileView struct {
	App, Slot, ID, Path, Name string
	Back, Raw, Download       string
	Size                      int64
	Kind                      string
	Text                      string
	Truncated                 bool
	Lines                     int
	Rows                      []hexRow
	PrevOff, NextOff          string
	Info                      [][2]string
	Image                     bool
}

var imageTypes = map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}

func (s *Server) whFileView(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app, slot, id, p := r.PathValue("app"), r.PathValue("slot"), r.PathValue("id"), r.PathValue("path")
	if api.ValidatePath(p, 64) != nil {
		wv.errorPage(404)
		return
	}
	fh, err := s.Svc.OpenFile(r.Context(), wv.principal(), app, slot, id, p)
	if err != nil {
		var pr *api.Problem
		if errors.As(err, &pr) && pr.Code == api.CodeEncrypted {
			http.Redirect(w, r, wv.snapLinks(app, slot, id), http.StatusSeeOther) // #nosec G710 -- escaped route under the link prefix
			return
		}
		s.tokenError(wv, err)
		return
	}
	defer func() {
		if c, ok := fh.Reader.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	base := wv.snapLinks(app, slot, id)
	v := fileView{App: app, Slot: slot, ID: id, Path: p, Name: path.Base(p), Size: fh.Size, Back: base,
		Raw: base + "/raw/" + escSegs(p)}
	ext := strings.ToLower(path.Ext(p))
	v.Info = [][2]string{{"Path", p}, {"Size", fmtBytes(float64(fh.Size))}, {"Modified", fh.ModTime.UTC().Format("2006-01-02 15:04:05 UTC")}}
	if _, ok := imageTypes[ext]; ok && fh.Size <= 20<<20 {
		v.Kind, v.Image = "image", true
		wv.render("file", 200, v)
		return
	}
	n := int64(viewTextMax)
	off := int64(0)
	head := make([]byte, 8192)
	hn, _ := io.ReadFull(fh.Reader, head)
	head = head[:hn]
	_, _ = fh.Reader.Seek(0, io.SeekStart)
	isText := utf8.Valid(head) && !bytes.Contains(head, []byte{0}) || (hn == 8192 && utf8.Valid(head[:hn-3]) && !bytes.Contains(head, []byte{0}))
	if isText {
		buf := make([]byte, n+1)
		rn, _ := io.ReadFull(fh.Reader, buf)
		buf = buf[:rn]
		if int64(rn) > n {
			buf, v.Truncated = buf[:n], true
		}
		txt := strings.ToValidUTF8(string(buf), "\uFFFD")
		if ext == ".json" && !v.Truncated {
			var out bytes.Buffer
			if json.Indent(&out, buf, "", "  ") == nil {
				txt = out.String()
			}
		}
		v.Kind, v.Text, v.Lines = "text", txt, strings.Count(txt, "\n")+1
		wv.render("file", 200, v)
		return
	}
	if base := strings.ToLower(path.Base(p)); base == "level.dat" || base == "level.dat_old" || ext == ".nbt" {
		if raw, err := io.ReadAll(io.LimitReader(fh.Reader, 8<<20)); err == nil {
			if li, err := detect.ParseLevelDat(raw); err == nil && li.Name != "" {
				v.Info = append(v.Info, [2]string{"World name", li.Name}, [2]string{"Game version", li.Version},
					[2]string{"Last played", li.LastPlayed.UTC().Format("2006-01-02 15:04 UTC")},
					[2]string{"Hardcore", fmt.Sprint(li.Hardcore)})
				v.Kind = "nbt"
			}
		}
		_, _ = fh.Reader.Seek(0, io.SeekStart)
	}
	if v.Kind == "" {
		v.Kind = "binary"
	}
	fmt.Sscanf(r.URL.Query().Get("offset"), "%d", &off)
	if off < 0 || off >= fh.Size {
		off = 0
	}
	off -= off % 16
	_, _ = fh.Reader.Seek(off, io.SeekStart)
	chunk := make([]byte, viewHexPage)
	cn, _ := io.ReadFull(fh.Reader, chunk)
	chunk = chunk[:cn]
	for i := 0; i < len(chunk); i += 16 {
		end := min(i+16, len(chunk))
		var hx, as strings.Builder
		for j := i; j < end; j++ {
			fmt.Fprintf(&hx, "%02x ", chunk[j])
			if chunk[j] >= 32 && chunk[j] < 127 {
				as.WriteByte(chunk[j])
			} else {
				as.WriteByte('.')
			}
		}
		v.Rows = append(v.Rows, hexRow{fmt.Sprintf("%08x", off+int64(i)), hx.String(), as.String()})
	}
	if off > 0 {
		v.PrevOff = fmt.Sprint(max(0, off-viewHexPage))
	}
	if off+int64(cn) < fh.Size {
		v.NextOff = fmt.Sprint(off + int64(cn))
	}
	wv.render("file", 200, v)
}

func (s *Server) whFileRaw(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	p := r.PathValue("path")
	if api.ValidatePath(p, 64) != nil {
		wv.errorPage(404)
		return
	}
	fh, err := s.Svc.OpenFile(r.Context(), wv.principal(), r.PathValue("app"), r.PathValue("slot"), r.PathValue("id"), p)
	if err != nil {
		s.tokenError(wv, err)
		return
	}
	defer func() {
		if c, ok := fh.Reader.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	if ct, ok := imageTypes[strings.ToLower(path.Ext(p))]; ok && r.URL.Query().Get("download") != "1" {
		h.Set("Content-Type", ct)
		h.Set("Content-Disposition", "inline")
	} else {
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(p)+`"`)
	}
	http.ServeContent(w, r, "", fh.ModTime, fh.Reader)
}

type diffLine struct{ Kind, Text string }

type diffView struct {
	App, Slot, A, B, Back string
	Entries               []diffRow
	Text                  []diffLine
	TextPath              string
	Skipped               string
	Counts                map[string]int
}

type diffRow struct{ Path, Kind, Href, Compare string }

func (s *Server) whDiff(w http.ResponseWriter, r *http.Request) {
	wv := webFrom(r)
	if !wv.requireAuth() {
		return
	}
	app, slot, a, b := r.PathValue("app"), r.PathValue("slot"), r.PathValue("id"), r.PathValue("other")
	ents, err := s.Svc.Diff(r.Context(), wv.principal(), app, slot, a, b)
	if err != nil {
		var pr *api.Problem
		if errors.As(err, &pr) && pr.Code == api.CodeEncrypted {
			http.Redirect(w, r, wv.snapLinks(app, slot, a), http.StatusSeeOther) // #nosec G710 -- escaped route under the link prefix
			return
		}
		s.tokenError(wv, err)
		return
	}
	baseA, baseB := wv.snapLinks(app, slot, a), wv.snapLinks(app, slot, b)
	v := diffView{App: app, Slot: slot, A: a, B: b, Back: baseA, Counts: map[string]int{}}
	for _, e := range ents {
		row := diffRow{Path: e.Path, Kind: e.Kind}
		if e.Kind != "removed" {
			row.Href = baseB + "/view/" + escSegs(e.Path)
		} else {
			row.Href = baseA + "/view/" + escSegs(e.Path)
		}
		if e.Kind == "changed" {
			row.Compare = baseA + "/diff/" + url.PathEscape(b) + "?file=" + url.QueryEscape(e.Path)
		}
		v.Entries = append(v.Entries, row)
		v.Counts[e.Kind]++
	}
	if f := r.URL.Query().Get("file"); f != "" && api.ValidatePath(f, 64) == nil {
		v.TextPath = f
		ta, ok1 := s.readText(wv, app, slot, a, f)
		tb, ok2 := s.readText(wv, app, slot, b, f)
		if !ok1 || !ok2 {
			v.Skipped = "This file is binary or too large for a text comparison."
		} else if lines := lineDiff(strings.Split(ta, "\n"), strings.Split(tb, "\n")); lines == nil {
			v.Skipped = "The files are too long for an inline comparison."
		} else {
			v.Text = lines
		}
	}
	wv.render("diff", 200, v)
}

func (s *Server) readText(wv *webReq, app, slot, id, p string) (string, bool) {
	fh, err := s.Svc.OpenFile(wv.r.Context(), wv.principal(), app, slot, id, p)
	if err != nil || fh.Size > viewTextMax {
		return "", false
	}
	defer func() {
		if c, ok := fh.Reader.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	b, err := io.ReadAll(io.LimitReader(fh.Reader, viewTextMax+1))
	if err != nil || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", false
	}
	return string(b), true
}

// lineDiff is an LCS line diff that collapses long unchanged runs.
func lineDiff(a, b []string) []diffLine {
	if len(a) > diffMaxLine || len(b) > diffMaxLine {
		return nil
	}
	n, m := len(a), len(b)
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var out []diffLine
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			out = append(out, diffLine{" ", a[i]})
			i++
			j++
		case i < n && (j == m || dp[i+1][j] >= dp[i][j+1]):
			out = append(out, diffLine{"-", a[i]})
			i++
		default:
			out = append(out, diffLine{"+", b[j]})
			j++
		}
	}
	var res []diffLine
	for k := 0; k < len(out); {
		if out[k].Kind != " " {
			res = append(res, out[k])
			k++
			continue
		}
		e := k
		for e < len(out) && out[e].Kind == " " {
			e++
		}
		if e-k > 7 {
			res = append(res, out[k:k+3]...)
			res = append(res, diffLine{"~", fmt.Sprintf("%d unchanged lines", e-k-6)})
			res = append(res, out[e-3:e]...)
		} else {
			res = append(res, out[k:e]...)
		}
		k = e
	}
	return res
}
