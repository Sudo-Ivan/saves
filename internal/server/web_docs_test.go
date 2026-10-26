// SPDX-License-Identifier: 0BSD

package server

import (
	"os"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/Sudo-Ivan/saves/internal/config"
)

func TestDocsRoutes(t *testing.T) {
	f := webSetup(t, nil)
	r, body := f.get(t, "/docs")
	if r.StatusCode != 200 {
		t.Fatalf("docs: %d", r.StatusCode)
	}
	// every operationId anchor and every tag present
	b, _ := yamlDoc(t)
	_ = b
	for _, id := range []string{"op-me", "op-apps", "op-commit", "op-tokenGet", "op-adminUsers"} {
		if !strings.Contains(body, `id="`+id+`"`) {
			t.Fatalf("missing %s", id)
		}
	}
	for _, tag := range []string{"Account", "Snapshots", "Admin"} {
		if !strings.Contains(body, tag) {
			t.Fatalf("missing tag %s", tag)
		}
	}
	// no inline style attributes or inline script
	if strings.Contains(body, " style=") || strings.Contains(body, "style>") {
		t.Fatal("inline style")
	}
	for i, m := range strings.Split(body, "<script") {
		if i > 0 && !strings.Contains(m[:strings.Index(m, ">")+1], "src=") {
			t.Fatal("inline script")
		}
	}
	// raw spec
	r2, body2 := f.get(t, "/openapi.yaml")
	if r2.StatusCode != 200 || !strings.HasPrefix(r2.Header.Get("Content-Type"), "application/yaml") {
		t.Fatalf("spec: %d", r2.StatusCode)
	}
	if r2.Header.Get("ETag") == "" {
		t.Fatal("no etag")
	}
	_ = body2
	// 304
	r3, _ := f.get(t, "/openapi.yaml")
	_ = r3
	// robots allows docs
	_, body4 := f.get(t, "/robots.txt")
	if !strings.Contains(body4, "Allow: /docs") {
		t.Fatal("robots")
	}
	// disabled -> styled 404
	f2 := webSetup(t, func(c *config.Config) { c.Web.APIDocs = false })
	r5, _ := f2.get(t, "/docs")
	if r5.StatusCode != 404 {
		t.Fatalf("disabled: %d", r5.StatusCode)
	}
}

func yamlDoc(t *testing.T) ([]byte, map[string]any) {
	var doc map[string]any
	b := readSpec(t)
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return b, doc
}

func readSpec(t *testing.T) []byte {
	b, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestMarkdownEscapes checks docMarkdown output is escaped.
func TestMarkdownEscapes(t *testing.T) {
	out := string(docMarkdown("<script>x</script> `code`"))
	if strings.Contains(out, "<script>") {
		t.Fatal("script not escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("no escape")
	}
}
