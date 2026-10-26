// SPDX-License-Identifier: 0BSD

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"

	apispec "github.com/Sudo-Ivan/saves/api"
	yaml "go.yaml.in/yaml/v3"
)

// docView is the parsed spec for the reference page.
type docView struct {
	Title, Version, Desc string
	Server               string
	Tags                 []docTag
}

type docTag struct {
	Name string
	Ops  []docOp
}

type docOp struct {
	ID, Method, Path, Summary, Desc string
	Params                          []docParam
	ReqBody                         *docBody
	Responses                       []docResp
	Samples                         []docSample
}

type docParam struct {
	Name, In, Type, Desc string
	Required             bool
}

type docBody struct {
	Type, Schema string
	Example      string
}

type docResp struct {
	Status, Desc, Type, Schema, Example string
}

type docSample struct {
	Lang, Source string
}

var parsedSpec *docView
var specETag string

func (s *Server) initDocs() error {
	v, err := parseSpec(apispec.Spec())
	if err != nil {
		return err
	}
	parsedSpec = v
	h := sha256.Sum256(apispec.Spec())
	specETag = `"` + hex.EncodeToString(h[:16]) + `"`
	return nil
}

func parseSpec(b []byte) (*docView, error) {
	var root map[string]any
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	get := func(m map[string]any, k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	v := &docView{}
	if info, ok := root["info"].(map[string]any); ok {
		v.Title = get(info, "title")
		v.Version = get(info, "version")
		v.Desc = get(info, "description")
	}
	if sv, ok := root["servers"].([]any); ok && len(sv) > 0 {
		v.Server = get(sv[0].(map[string]any), "url")
	}
	// tag order from top-level tags
	tagOrder := map[string]int{}
	if ts, ok := root["tags"].([]any); ok {
		for i, t := range ts {
			if tm, ok := t.(map[string]any); ok {
				tagOrder[get(tm, "name")] = i
			}
		}
	}
	byTag := map[string][]docOp{}
	if paths, ok := root["paths"].(map[string]any); ok {
		var order []string
		for p := range paths {
			order = append(order, p)
		}
		sort.Strings(order)
		for _, p := range order {
			methods, ok := paths[p].(map[string]any)
			if !ok {
				continue
			}
			for _, m := range []string{"get", "post", "put", "patch", "delete", "head"} {
				op, ok := methods[m].(map[string]any)
				if !ok {
					continue
				}
				d := docOp{ID: get(op, "operationId"), Method: strings.ToUpper(m),
					Path: p, Summary: get(op, "summary"), Desc: get(op, "description")}
				if pl, ok := op["parameters"].([]any); ok {
					for _, pi := range pl {
						pm, ok := pi.(map[string]any)
						if !ok {
							continue
						}
						if r, ok := pm["$ref"].(string); ok {
							pm = resolveRef(root, r, 0)
						}
						dp := docParam{Name: get(pm, "name"), In: get(pm, "in"),
							Desc: get(pm, "description")}
						if sch, ok := pm["schema"].(map[string]any); ok {
							dp.Type = get(sch, "type")
						}
						if rq, ok := pm["required"].(bool); ok {
							dp.Required = rq
						}
						d.Params = append(d.Params, dp)
					}
				}
				if rb, ok := op["requestBody"].(map[string]any); ok {
					d.ReqBody = parseBody(root, rb)
				}
				if rs, ok := op["responses"].(map[string]any); ok {
					var codes []string
					for c := range rs {
						codes = append(codes, c)
					}
					sort.Strings(codes)
					for _, c := range codes {
						rm, ok := rs[c].(map[string]any)
						if !ok {
							continue
						}
						if r, ok := rm["$ref"].(string); ok {
							rm = resolveRef(root, r, 0)
						}
						dr := docResp{Status: c, Desc: get(rm, "description")}
						if ct, ok := rm["content"].(map[string]any); ok {
							for typ, cm := range ct {
								dr.Type = typ
								if cmm, ok := cm.(map[string]any); ok {
									if sch, ok := cmm["schema"].(map[string]any); ok {
										dr.Schema = schemaText(root, sch, 0)
									}
									if ex, ok := cmm["example"]; ok {
										dr.Example = exText(ex)
									}
								}
								break
							}
						}
						d.Responses = append(d.Responses, dr)
					}
				}
				if xs, ok := op["x-codeSamples"].([]any); ok {
					for _, x := range xs {
						if xm, ok := x.(map[string]any); ok {
							d.Samples = append(d.Samples, docSample{Lang: get(xm, "lang"), Source: get(xm, "source")})
						}
					}
				}
				tags, _ := op["tags"].([]any)
				tag := "Misc"
				if len(tags) > 0 {
					tag = fmt.Sprint(tags[0])
				}
				byTag[tag] = append(byTag[tag], d)
			}
		}
	}
	var names []string
	for t := range byTag {
		names = append(names, t)
	}
	sort.Slice(names, func(i, j int) bool { return tagOrder[names[i]] < tagOrder[names[j]] })
	for _, n := range names {
		v.Tags = append(v.Tags, docTag{Name: n, Ops: byTag[n]})
	}
	return v, nil
}

func parseBody(root map[string]any, rb map[string]any) *docBody {
	out := &docBody{}
	if ct, ok := rb["content"].(map[string]any); ok {
		for typ, cm := range ct {
			out.Type = typ
			if cmm, ok := cm.(map[string]any); ok {
				if sch, ok := cmm["schema"].(map[string]any); ok {
					out.Schema = schemaText(root, sch, 0)
				}
				if ex, ok := cmm["example"]; ok {
					out.Example = exText(ex)
				}
			}
			break
		}
	}
	return out
}

func resolveRef(root map[string]any, ref string, depth int) map[string]any {
	if depth > 6 || !strings.HasPrefix(ref, "#/") {
		return nil
	}
	cur := any(root)
	for _, p := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	if m, ok := cur.(map[string]any); ok {
		return m
	}
	return nil
}

func schemaText(root map[string]any, sch map[string]any, depth int) string {
	if depth > 5 {
		return "object"
	}
	if r, ok := sch["$ref"].(string); ok {
		target := resolveRef(root, r, depth+1)
		name := r[strings.LastIndex(r, "/")+1:]
		if target == nil {
			return name
		}
		return name + " { " + schemaText(root, target, depth+1) + " }"
	}
	t, _ := sch["type"].(string)
	if t == "object" {
		var parts []string
		if props, ok := sch["properties"].(map[string]any); ok {
			for k, p := range props {
				if pm, ok := p.(map[string]any); ok {
					parts = append(parts, k+": "+schemaText(root, pm, depth+1))
				}
			}
		}
		if len(parts) > 0 {
			return "{ " + strings.Join(parts, ", ") + " }"
		}
		return "object"
	}
	if t == "array" {
		if it, ok := sch["items"].(map[string]any); ok {
			return "[]" + schemaText(root, it, depth+1)
		}
	}
	if en, ok := sch["enum"].([]any); ok {
		var s []string
		for _, e := range en {
			s = append(s, fmt.Sprint(e))
		}
		return t + " (" + strings.Join(s, "|") + ")"
	}
	if t == "" {
		return "any"
	}
	return t
}

func exText(ex any) string {
	if s, ok := ex.(string); ok {
		return s
	}
	b, _ := yaml.Marshal(ex)
	return strings.TrimSpace(string(b))
}

// whDocs renders the API reference page.
func (s *Server) whDocs(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.Web.APIDocs {
		wv := &webReq{s: s, w: w, r: r, web: s.web}
		wv.errorPage(404)
		return
	}
	if parsedSpec == nil {
		if err := s.initDocs(); err != nil {
			http.Error(w, "spec", 500)
			return
		}
	}
	wv := &webReq{s: s, w: w, r: r, web: s.web}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = wv
	t := s.docTmpl()
	w.WriteHeader(200)
	_ = t.Execute(w, parsedSpec)
}

// whSpec serves the raw spec document.
func (s *Server) whSpec(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.Web.APIDocs {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("If-None-Match") == specETag {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("ETag", specETag)
	_, _ = w.Write(apispec.Spec())
}

func (s *Server) docTmpl() *template.Template {
	return template.Must(template.New("docs").Funcs(template.FuncMap{
		"md":    docMarkdown,
		"lower": strings.ToLower,
		"tagid": func(s string) string { return strings.ReplaceAll(strings.ToLower(s), " ", "-") },
	}).Parse(docTmplSrc))
}

// docMarkdown renders markdown-ish text to escaped HTML (paragraphs,
// inline code, fenced blocks, lists, headings, no raw HTML).
func docMarkdown(s string) template.HTML {
	var out strings.Builder
	esc := template.HTMLEscapeString
	parts := strings.Split(s, "\n")
	inCode := false
	for i, ln := range parts {
		if strings.HasPrefix(ln, "```") {
			if inCode {
				out.WriteString("</code></pre>")
				inCode = false
			} else {
				out.WriteString("<pre class=\"docs__pre\"><code>")
				inCode = true
			}
			continue
		}
		if inCode {
			out.WriteString(esc(ln) + "\n")
			continue
		}
		if strings.HasPrefix(ln, "### ") {
			out.WriteString("<h3>" + inlineMD(ln[4:]) + "</h3>")
		} else if strings.HasPrefix(ln, "## ") {
			out.WriteString("<h2>" + inlineMD(ln[3:]) + "</h2>")
		} else if strings.HasPrefix(ln, "# ") {
			out.WriteString("<h1>" + inlineMD(ln[2:]) + "</h1>")
		} else if strings.HasPrefix(ln, "- ") {
			out.WriteString("<ul><li>" + inlineMD(ln[2:]) + "</li></ul>")
		} else if strings.TrimSpace(ln) != "" {
			out.WriteString("<p>" + inlineMD(ln) + "</p>")
		}
		_ = i
	}
	if inCode {
		out.WriteString("</code></pre>")
	}
	return template.HTML(out.String()) //nolint:gosec -- content escaped
}

func inlineMD(s string) string {
	esc := template.HTMLEscapeString
	// `code` spans
	var out strings.Builder
	for {
		a := strings.Index(s, "`")
		if a < 0 {
			out.WriteString(esc(s))
			break
		}
		b := strings.Index(s[a+1:], "`")
		if b < 0 {
			out.WriteString(esc(s))
			break
		}
		out.WriteString(esc(s[:a]) + "<code>" + esc(s[a+1:a+1+b]) + "</code>")
		s = s[a+1+b+1:]
	}
	return out.String()
}

var docTmplSrc = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>API reference - {{.Title}}</title>
<link rel="stylesheet" href="static/tokens.css">
<link rel="stylesheet" href="static/base.css">
<link rel="stylesheet" href="static/app.css">
</head><body class="page">
<main id="main" class="docs">
<header class="docs__head">
<h1>{{.Title}} <span class="docs__ver">{{.Version}}</span></h1>
<p class="docs__server">Server: <code>{{.Server}}</code> · OpenAPI 3.1 · <a href="openapi.yaml">Download spec</a></p>
</header>
<details class="docs__toc docs__toc--mobile"><summary>Contents</summary>{{template "toc" .}}</details>
<aside class="docs__toc">{{template "toc" .}}</aside>
<section class="docs__body">
{{if .Desc}}<section class="docs__sec"><h2>Getting started</h2>{{md .Desc}}</section>{{end}}
<section class="docs__sec"><h2>Authentication</h2><p>Every request sends an sv1_ bearer token in the Authorization header. Tokens are minted with POST /v1/tokens or by an admin. Errors are RFC 9457 problems with a stable code field; 429 responses carry Retry-After.</p></section>
{{range .Tags}}<section class="docs__tag" id="tag-{{tagid .Name}}"><h2>{{.Name}}</h2>
{{range .Ops}}<article class="docs__op" id="op-{{.ID}}">
<header class="docs__ophead"><span class="method method--{{lower .Method}}">{{.Method}}</span> <code class="docs__path">{{.Path}}</code></header>
<p class="docs__sum">{{.Summary}}</p>
{{if .Desc}}<div class="docs__desc">{{md .Desc}}</div>{{end}}
{{if .Params}}<table class="table"><thead><tr><th>Parameter</th><th>In</th><th>Type</th><th>Required</th><th>Description</th></tr></thead><tbody>
{{range .Params}}<tr><td><code>{{.Name}}</code></td><td>{{.In}}</td><td>{{.Type}}</td><td>{{.Required}}</td><td>{{.Desc}}</td></tr>{{end}}
</tbody></table>{{end}}
{{if .ReqBody}}<h3>Request body <code>{{.ReqBody.Type}}</code></h3>
{{if .ReqBody.Schema}}<pre class="docs__pre"><code>{{.ReqBody.Schema}}</code></pre>{{end}}
{{if .ReqBody.Example}}<pre class="docs__pre"><code>{{.ReqBody.Example}}</code></pre>{{end}}{{end}}
{{if .Responses}}<h3>Responses</h3><table class="table"><tbody>
{{range .Responses}}<tr><td><code>{{.Status}}</code></td><td>{{.Desc}}{{if .Type}} <code>{{.Type}}</code>{{end}}{{if .Schema}}<pre class="docs__pre"><code>{{.Schema}}</code></pre>{{end}}{{if .Example}}<pre class="docs__pre"><code>{{.Example}}</code></pre>{{end}}</td></tr>{{end}}
</tbody></table>{{end}}
{{range .Samples}}<pre class="docs__pre"><code>{{.Source}}</code></pre>{{end}}
</article>{{end}}
</section>{{end}}
</section>
</main>
</body></html>
{{define "toc"}}<nav class="docs__tocnav">{{range .Tags}}<a href="#tag-{{tagid .Name}}">{{.Name}}</a>{{range .Ops}}<a class="docs__tocop" href="#op-{{.ID}}"><span class="method method--{{lower .Method}}">{{.Method}}</span> {{.Path}}</a>{{end}}{{end}}</nav>{{end}}`
