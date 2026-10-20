// SPDX-License-Identifier: 0BSD

package detect

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// fakeReg is an in-memory RegistryReader.
type fakeReg struct {
	keys map[string][]string
	vals map[string]string
}

func (f fakeReg) Get(root, p, name string) (string, error) {
	return f.vals[root+"\\"+p+"\\"+name], nil
}

func (f fakeReg) ListKeys(root, p string) ([]string, error) {
	return f.keys[root+"\\"+p], nil
}

// buildHome constructs the full fake tree.
func buildHome(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	mk := func(p string) { t.Helper(); os.MkdirAll(filepath.Join(h, p), 0o755) }
	wr := func(p, c string) {
		mk(filepath.Dir(p))
		os.WriteFile(filepath.Join(h, p), []byte(c), 0o644)
	}
	// steam primary + second library
	mk(".steam/steam/steamapps")
	wr(".steam/steam/steamapps/libraryfolders.vdf",
		`"libraryfolders"{"0"{"path" "`+h+`/.steam/steam"}`+
			`"1"{"path" "`+h+`/lib2"}}`)
	wr(".steam/steam/steamapps/appmanifest_1.acf",
		`"AppState"{"appid" "1" "name" "GameOne" "installdir" "g1"}`)
	mk(".steam/steam/steamapps/common/g1")
	mk(".steam/steam/steamapps/compatdata/1/pfx/drive_c/users/user/Documents/My Games/g1save")
	mk("lib2/steamapps/common")
	// wine
	mk(".wine/drive_c/users/user/AppData/Roaming/wsave")
	wr(".wine/system.reg", "")
	// heroic gog
	wr(".config/heroic/gog_store/installed.json",
		`{"g1":{"title":"GogGame","install_path":"`+h+`/gog/g1","productId":"55"}}`)
	wr(".config/heroic/GamesConfig/g1.json", `{"winePrefix":"`+h+`/gog/pfx"}`)
	// prism instance 2 worlds (one with level.dat)
	wr(".local/share/PrismLauncher/instances/i1/instance.cfg", "")
	mk(".local/share/PrismLauncher/instances/i1/minecraft/saves/W1")
	mk(".local/share/PrismLauncher/instances/i1/minecraft/saves/W2")
	os.WriteFile(filepath.Join(h, ".local/share/PrismLauncher/instances/i1/minecraft/saves/W1/level.dat"), mkNBT(), 0o644)
	os.WriteFile(filepath.Join(h, ".local/share/PrismLauncher/instances/i1/minecraft/saves/W2/level.dat"), mkNBT(), 0o644)
	// bedrock
	mk(".local/share/mcpelauncher/games/com.mojang/minecraftWorlds/wA")
	mk(".local/share/mcpelauncher/games/com.mojang/minecraftWorlds/wB")
	wr(".local/share/mcpelauncher/games/com.mojang/minecraftWorlds/wA/levelname.txt", "WorldA")
	wr(".local/share/mcpelauncher/games/com.mojang/minecraftWorlds/wB/levelname.txt", "WorldB")
	return h
}

func TestE2E(t *testing.T) {
	h := buildHome(t)
	env := &Env{Home: h, XDGConfig: h + "/.config", XDGData: h + "/.local/share",
		OS: "linux", Getenv: os.Getenv}
	d := &Detector{Finders: []Finder{SteamFinder{}, PrefixFinder{},
		HeroicFinder{}, MinecraftFinder{}}}
	games, err := d.Detect(context.Background(), env, wrapFS{os.DirFS("/"), h})
	if err != nil {
		t.Fatal(err)
	}
	var steam, gog, mc int
	for _, g := range games {
		switch g.Store {
		case "steam":
			steam++
		case "gog":
			gog++
		case "minecraft":
			mc++
		}
	}
	if steam != 1 || gog != 1 || mc != 4 {
		t.Fatalf("steam=%d gog=%d mc=%d %+v", steam, gog, mc, games)
	}
	var sg *Game
	for i := range games {
		if games[i].ID == "steam:1" {
			sg = &games[i]
		}
		if err := api.ValidateAppID(games[i].ID); err != nil {
			t.Fatalf("bad id %q: %v", games[i].ID, err)
		}
		if games[i].Slot != "" {
			if err := api.ValidateSlotName(games[i].Slot); err != nil {
				t.Fatalf("bad slot %q: %v", games[i].Slot, err)
			}
		}
	}
	// steam game has no save locations without manifest application
	if sg == nil || len(sg.Locations) != 0 {
		t.Fatal("steam game wrongly has locations")
	}
}

func TestGOGRegistry(t *testing.T) {
	reg := fakeReg{
		keys: map[string][]string{
			`HKLM\SOFTWARE\GOG.com\Games`: {"123"},
		},
		vals: map[string]string{
			`HKLM\SOFTWARE\GOG.com\Games\123\name`: "G Game",
			`HKLM\SOFTWARE\GOG.com\Games\123\path`: `C:\Games\G`,
		},
	}
	env := &Env{Registry: reg, OS: "windows"}
	g, _, err := GOGGalaxyFinder{}.Find(context.Background(), env, nil)
	if err != nil || len(g) != 1 || g[0].ID != "gog:123" {
		t.Fatalf("%+v %v", g, err)
	}
}
