// SPDX-License-Identifier: 0BSD

package config_test

import (
	"bytes"
	"os"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// TestDeployYAMLsParse validates all deploy/*.yaml files parse as YAML.
func TestDeployYAMLsParse(t *testing.T) {
	for _, f := range []string{
		"../../deploy/compose-small.yaml",
		"../../deploy/compose-ha.yaml",
		"../../deploy/k8s/k8s.yaml",
		"../../deploy/prometheus/alerts.yaml",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(f, err)
		}
		var v map[string]any
		if err := yaml.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	// k8s multi doc
	b, _ := os.ReadFile("../../deploy/k8s/k8s.yaml")
	d := yaml.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		var v map[string]any
		if err := d.Decode(&v); err != nil {
			break
		}
		if v != nil {
			n++
		}
	}
	if n < 10 {
		t.Fatalf("k8s docs %d", n)
	}
}
