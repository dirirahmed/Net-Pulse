// Net-Pulse v2: a network diagnostics engine with a thin CLI on top.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/dirirahmed/Net-Pulse/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "net-pulse:", err)
		os.Exit(1)
	}
}
