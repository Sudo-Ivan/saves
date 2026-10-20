package detect

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestSteamDbg(t *testing.T) {
	env := &Env{Home: "/tmp/steamhome", OS: "linux"}
	g, p, e := SteamFinder{}.Find(context.Background(), env, os.DirFS("/"))
	fmt.Println("games:", g, "pfx:", p, "err:", e)
}
