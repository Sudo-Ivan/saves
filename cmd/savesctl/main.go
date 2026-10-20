// SPDX-License-Identifier: 0BSD

// Command savesctl is the saves sync client CLI.
package main

import "fmt"

// version is the build version, overridden at link time.
var version = "dev"

func main() {
	fmt.Println("savesctl", version)
}
