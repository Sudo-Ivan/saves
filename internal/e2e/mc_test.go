// SPDX-License-Identifier: 0BSD

package e2e

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// levelDat builds a minimal gzip NBT level.dat.
func levelDat(t *testing.T, name string) []byte {
	t.Helper()
	var b bytes.Buffer
	wstr := func(s string) {
		binary.Write(&b, binary.BigEndian, int16(len(s)))
		b.WriteString(s)
	}
	b.WriteByte(10)
	wstr("")
	b.WriteByte(10)
	wstr("Data")
	b.WriteByte(8)
	wstr("LevelName")
	wstr(name)
	b.WriteByte(4)
	wstr("LastPlayed")
	binary.Write(&b, binary.BigEndian, time.Now().UnixMilli())
	b.WriteByte(0)
	b.WriteByte(0)
	var gz bytes.Buffer
	g := gzip.NewWriter(&gz)
	if _, err := g.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
	g.Close()
	return gz.Bytes()
}

func mkWorld(t *testing.T, dir, name string, regionBytes int) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, "region"), 0o755)
	os.MkdirAll(filepath.Join(dir, "playerdata"), 0o755)
	if err := os.WriteFile(filepath.Join(dir, "level.dat"), levelDat(t, name), 0o644); err != nil {
		t.Fatal(err)
	}
	if regionBytes > 0 {
		rnd := rand.New(rand.NewSource(42))
		buf := make([]byte, regionBytes)
		rnd.Read(buf)
		if err := os.WriteFile(filepath.Join(dir, "region", "r.0.0.mca"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "playerdata", "x.dat"), []byte("pd"), 0o644)
	os.WriteFile(filepath.Join(dir, "session.lock"), []byte{1}, 0o644)
}

func TestMinecraftE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	url, stop := startServer(t)
	defer stop()
	envA := deviceEnv(t, "A")
	hA := envHome(envA)
	mkWorld(t, hA+"/.minecraft/saves/My World", "My World", 24<<20)
	mkWorld(t, hA+"/.minecraft/saves/Creative", "Creative", 0)
	code, _, se := run(t, envA, "setup", "--server", url, "--register")
	if code != 0 {
		t.Fatalf("setup: %s", se)
	}
	code, out, _ := run(t, envA, "games", "list", "--json")
	if code != 0 {
		t.Fatalf("games: %d", code)
	}
	var rows []struct {
		ID, Title, Store, Slot string
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("games json: %v %q", err, out)
	}
	var w1, w2 bool
	for _, r := range rows {
		if r.ID == "minecraft-java" && r.Slot == "My World" && r.Title == "My World" {
			w1 = true
		}
		if r.ID == "minecraft-java" && r.Slot == "Creative" {
			w2 = true
		}
	}
	if !w1 || !w2 {
		t.Fatalf("worlds missing: %s", out)
	}
	code, _, _ = run(t, envA, "track", "auto")
	if code != 0 {
		t.Fatal("track auto")
	}
	// push
	code, out, _ = run(t, envA, "push", "--all", "--json")
	if code != 0 {
		t.Fatalf("push: %s", out)
	}
	// verify session.lock not in manifest: fetch manifest via snapshots
	_, snaps, _ := run(t, envA, "snapshots", "minecraft-java/My World")
	t.Logf("snapshots: %q", snaps)
	// delta: change 3 KiB mid file
	f, _ := os.OpenFile(hA+"/.minecraft/saves/My World/region/r.0.0.mca", os.O_RDWR, 0)
	f.WriteAt([]byte("DELTA-DELTA-DELTA-DELTA-DELTA-DELTA"), 12<<20)
	f.Close()
	_, out2, _ := run(t, envA, "push", "--all", "--json")
	t.Logf("delta push: %s", out2)
	var ds struct {
		UploadedBytes  int64 `json:"uploaded_bytes"`
		UploadedChunks int64 `json:"uploaded_chunks"`
	}
	for _, ln := range bytes.Split([]byte(out2), []byte("\n")) {
		if len(ln) == 0 {
			continue
		}
		var m map[string]any
		if json.Unmarshal(ln, &m) == nil && m["slot"] == "My World" {
			bb, _ := json.Marshal(m)
			json.Unmarshal(bb, &ds)
		}
	}
	t.Logf("delta uploaded_bytes=%d uploaded_chunks=%d", ds.UploadedBytes, ds.UploadedChunks)
	if ds.UploadedChunks > 3 {
		t.Fatalf("uploaded %d chunks", ds.UploadedChunks)
	}
	if ds.UploadedBytes >= 3<<20 {
		t.Fatalf("uploaded %d bytes", ds.UploadedBytes)
	}
	// no-change push is a no-op
	_, out3, _ := run(t, envA, "push", "--all", "--json")
	var un bool
	for _, ln := range bytes.Split([]byte(out3), []byte("\n")) {
		var m map[string]any
		if len(ln) > 0 && json.Unmarshal(ln, &m) == nil && m["slot"] == "My World" {
			un, _ = m["unchanged"].(bool)
		}
	}
	if !un {
		t.Fatalf("no-change push not unchanged: %s", out3)
	}
	// B pull
	envB := deviceEnv(t, "B")
	hB := envHome(envB)
	cfgp := hA + "/.config/saves/config.json"
	b, _ := os.ReadFile(cfgp)
	var jc struct{ Token string }
	json.Unmarshal(b, &jc)
	code, _, se = run(t, envB, "setup", "--server", url, "--token", jc.Token)
	if code != 0 {
		t.Fatalf("setup B: %s", se)
	}
	// manual tracks on B keep its state clean for delta sync
	os.MkdirAll(hB+"/.minecraft/saves/My World", 0o755)
	os.MkdirAll(hB+"/.minecraft/saves/Creative", 0o755)
	run(t, envB, "track", "add", "--path", hB+"/.minecraft/saves/My World", "--app", "minecraft-java", "--slot", "My World", "--key", "world")
	run(t, envB, "track", "add", "--path", hB+"/.minecraft/saves/Creative", "--app", "minecraft-java", "--slot", "Creative", "--key", "world")
	code, outp, sep := run(t, envB, "pull", "--all", "--json")
	t.Logf("pull: %s %s", outp, sep)
	if code != 0 {
		t.Fatalf("pull: %s", sep)
	}
	// compare files (session.lock must not exist remotely)
	if _, err := os.Stat(hB + "/.minecraft/saves/My World/session.lock"); !os.IsNotExist(err) {
		t.Fatal("session.lock was uploaded")
	}
	for _, rel := range []string{"region/r.0.0.mca", "playerdata/x.dat"} {
		a, _ := os.ReadFile(hA + "/.minecraft/saves/My World/" + rel)
		bb, err := os.ReadFile(hB + "/.minecraft/saves/My World/" + rel)
		if err != nil || !bytes.Equal(a, bb) {
			t.Fatalf("file %s differs", rel)
		}
	}
	// delta pull on B: change again on A, push, B sync pulls small
	f, _ = os.OpenFile(hA+"/.minecraft/saves/My World/region/r.0.0.mca", os.O_RDWR, 0)
	f.WriteAt([]byte("MORE-DELTA-1234"), 12<<20)
	f.Close()
	run(t, envA, "push", "--all")
	code, outs, _ := run(t, envB, "sync", "--all", "--json")
	t.Logf("sync out: %s", outs)
	if code != 0 {
		t.Fatalf("sync: %d %s", code, outs)
	}
	var dl int64
	for _, ln := range bytes.Split([]byte(outs), []byte("\n")) {
		var m map[string]any
		if len(ln) > 0 && json.Unmarshal(ln, &m) == nil {
			if v, ok := m["downloaded_bytes"].(float64); ok {
				dl += int64(v)
			}
		}
	}
	t.Logf("sync downloaded_bytes=%d", dl)
	if dl >= 3<<20 {
		t.Fatalf("sync downloaded %d", dl)
	}
}
