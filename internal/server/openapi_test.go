// SPDX-License-Identifier: 0BSD

package server

import (
	"os"
	"regexp"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// TestOpenAPICoversRoutes verifies every registered route is in the spec.
func TestOpenAPICoversRoutes(t *testing.T) {
	b, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string                    `yaml:"openapi"`
		Info    map[string]any            `yaml:"info"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI == "" || doc.Info == nil {
		t.Fatal("missing top fields")
	}
	// collect spec ops
	spec := map[string]bool{}
	var ids []string
	for p, methods := range doc.Paths {
		for m, op := range methods {
			mo, ok := op.(map[string]any)
			if !ok {
				continue
			}
			id, _ := mo["operationId"].(string)
			if id != "" {
				ids = append(ids, id)
			}
			spec[strings.ToUpper(m)+" "+p] = true
		}
	}
	// unique operationIds
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("dup operationId %s", id)
		}
		seen[id] = true
	}
	// registered routes from the source table.
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`HandleFunc\("([A-Z]+) (/[^"]+)"`)
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		p := strings.ReplaceAll(m[2], "{path...}", "{path}")
		key := m[1] + " " + p
		if !spec[key] {
			t.Errorf("route %s missing from openapi.yaml", key)
		}
	}
	if len(spec) < 30 {
		t.Fatalf("only %d ops in spec", len(spec))
	}
}
