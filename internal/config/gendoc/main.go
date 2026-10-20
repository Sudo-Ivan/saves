// SPDX-License-Identifier: 0BSD

// Command gendoc renders docs/config.md from the Config struct tags.
package main

import (
	"fmt"

	"github.com/Sudo-Ivan/saves/internal/config"
)

func main() {
	fmt.Print(config.RenderDoc())
}
