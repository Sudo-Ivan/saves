// SPDX-License-Identifier: 0BSD

package detect

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestManifestPerf(t *testing.T) {
	if testing.Short() || os.Getenv("SAVES_TEST_LUDUSAVI") == "" {
		t.Skip("set SAVES_TEST_LUDUSAVI=1")
	}
	f, err := os.Open("/tmp/manifest.yaml")
	if err != nil {
		t.Skip("no manifest")
	}
	defer f.Close()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	t0 := time.Now()
	ix, err := ParseManifest(f)
	if err != nil {
		t.Fatal(err)
	}
	dt := time.Since(t0)
	runtime.ReadMemStats(&m2)
	t.Logf("games=%d parse=%v alloc=%dMiB", len(ix.Games), dt, (m2.TotalAlloc-m1.TotalAlloc)>>20)
	_ = ix.Save(t.TempDir() + "/i.json")
}
