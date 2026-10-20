// SPDX-License-Identifier: 0BSD

package main

import (
	"os"

	"github.com/Sudo-Ivan/saves/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[1:]))
}
