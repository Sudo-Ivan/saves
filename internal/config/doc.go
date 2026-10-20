// SPDX-License-Identifier: 0BSD

package config

import (
	"fmt"
	"reflect"
	"strings"
)

// RenderDoc produces the markdown configuration reference from the
// struct tags. It backs the make docs target and the drift test.
func RenderDoc() string {
	var b strings.Builder
	b.WriteString("# savesd configuration reference\n\n")
	b.WriteString("Generated from internal/config struct tags by internal/config/gendoc. Do not edit.\n\n")
	b.WriteString("Every duration accepts human strings like 30s, 5m, 24h, 90d, and every\n")
	b.WriteString("size accepts strings like 512MiB or 10GB. Bare numbers mean seconds and bytes.\n\n")
	b.WriteString("Environment overrides: SAVES_<SECTION>_<KEY> set any scalar, for example\n")
	b.WriteString("SAVES_LISTEN_ADDR or SAVES_LOG_LEVEL. Secret fields accept a <name>_file\n")
	b.WriteString("sibling that reads the value from a file, or the matching *_FILE environment\n")
	b.WriteString("variable. Sections reloadable on SIGHUP: quota, limits, log, auth.\n\n")
	walkDoc(&b, reflect.TypeOf(Config{}), "", 0)
	return b.String()
}

var scalarTypes = map[reflect.Type]bool{
	reflect.TypeOf(Duration(0)): true,
	reflect.TypeOf(Size(0)):     true,
}

func walkDoc(b *strings.Builder, t reflect.Type, path string, depth int) {
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		jname, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if jname == "" || jname == "-" {
			continue
		}
		doc := f.Tag.Get("doc")
		full := jname
		if path != "" {
			full = path + "." + jname
		}
		ft := f.Type
		switch {
		case ft.Kind() == reflect.Struct && !scalarTypes[ft]:
			fmt.Fprintf(b, "%s %s\n\n", strings.Repeat("#", depth+2), full)
			if doc != "" {
				fmt.Fprintf(b, "%s\n\n", doc)
			}
			walkDoc(b, ft, full, depth+1)
		case ft.Kind() == reflect.Map:
			fmt.Fprintf(b, "- %s (map): %s\n", full, doc)
		case ft.Kind() == reflect.Slice:
			fmt.Fprintf(b, "- %s (list): %s\n", full, doc)
		default:
			secret := ""
			if hasSecretTag(f) {
				secret = " (secret)"
			}
			fmt.Fprintf(b, "- %s%s: %s\n", full, secret, doc)
		}
	}
}
