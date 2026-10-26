// SPDX-License-Identifier: 0BSD

package server

import (
	"os"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

type opDoc struct {
	Summary   string         `yaml:"summary"`
	Tags      []string       `yaml:"tags"`
	OpID      string         `yaml:"operationId"`
	Responses map[string]any `yaml:"responses"`
	Desc      string         `yaml:"description"`
}

// TestOpenAPIStruct checks summary, tags, 401 coverage and refs.
func TestOpenAPIStruct(t *testing.T) {
	b, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]opDoc `yaml:"paths"`
		Comps map[string]any              `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	text := string(b)
	// every $ref resolves inside the doc
	for _, ref := range findRefs(text) {
		path := strings.TrimPrefix(ref, "#/")
		parts := strings.Split(path, "/")
		var cur any = map[string]any{"paths": doc.Paths, "components": doc.Comps}
		var full any = func() any { var x any; _ = x; return nil }()
		_ = full
		// resolve in the raw doc
		var root map[string]any
		_ = yaml.Unmarshal(b, &root)
		cur = root
		ok := true
		for _, p := range parts {
			m, isMap := cur.(map[string]any)
			if !isMap {
				ok = false
				break
			}
			cur, isMap = m[p]
			if !isMap {
				ok = false
				break
			}
		}
		if !ok {
			t.Fatalf("unresolved ref %s", ref)
		}
	}
	for path, methods := range doc.Paths {
		for meth, op := range methods {
			name := meth + " " + path
			if op.Summary == "" {
				t.Fatalf("%s no summary", name)
			}
			if len(op.Tags) == 0 {
				t.Fatalf("%s no tags", name)
			}
			if op.OpID == "" {
				t.Fatalf("%s no operationId", name)
			}
			if path == "/v1/register" || path == "/v1/events" && meth == "get" {
				continue
			}
			if _, ok := op.Responses["401"]; !ok && path != "/v1/register" {
				if _, ok2 := op.Responses["403"]; !ok2 {
					t.Fatalf("%s no 401/403", name)
				}
			}
		}
	}
}

func findRefs(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "$ref:"); i >= 0 {
			v := strings.TrimSpace(strings.Trim(line[i+5:], "'\""))
			if strings.HasPrefix(v, "#/") {
				out = append(out, v)
			}
		}
	}
	return out
}
