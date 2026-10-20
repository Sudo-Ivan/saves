// SPDX-License-Identifier: 0BSD

// smoke runs detection against the real home directory.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Sudo-Ivan/saves/internal/detect"
)

func main() {
	env := detect.DefaultEnv()
	games, err := detect.DefaultDetector().Detect(context.Background(), env, os.DirFS("/"))
	if err != nil {
		panic(err)
	}
	by := map[string]int{}
	for _, g := range games {
		by[g.Store]++
	}
	for k, v := range by {
		fmt.Printf("%s %d\n", k, v)
	}
	fmt.Println("total", len(games))
}
