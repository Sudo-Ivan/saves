// SPDX-License-Identifier: 0BSD

// savesctl is the saves CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Sudo-Ivan/saves/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Main(ctx, cli.DefaultEnv(), os.Args[1:]))
}
