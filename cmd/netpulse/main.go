// Command netpulse is the single Net-Pulse binary.
//
//	netpulse scan [flags] <target>   one-off network diagnostics (the CLI)
//	netpulse serve [flags]           monitoring agent + dashboard
//
// A bare `netpulse <target>` still runs a scan, so V1 and V2 invocations keep
// working.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dirirahmed/Net-Pulse/internal/agent"
	"github.com/dirirahmed/Net-Pulse/internal/cli"
)

// version is set at build time by the release workflow:
//
//	go build -ldflags "-X main.version=v3.0.0" ./cmd/netpulse
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "netpulse:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.Run(ctx, args, stdout, stderr)
	}
	switch args[0] {
	case "serve":
		agent.Version = version
		return agent.Run(ctx, args[1:], stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "netpulse", version)
		return nil
	case "scan":
		return cli.Run(ctx, args[1:], stdout, stderr)
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return nil
	}
	if !strings.HasPrefix(args[0], "-") && !looksLikeTarget(args[0]) {
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
	// Flags or a target with no subcommand: the pre-merge CLI form.
	return cli.Run(ctx, args, stdout, stderr)
}

// looksLikeTarget tells a mistyped subcommand ("sevre") from a bare
// hostname target ("localhost", "example.com", "1.1.1.1", "[::1]:443").
func looksLikeTarget(s string) bool {
	return strings.ContainsAny(s, ".:/[") || s == "localhost"
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Net-Pulse - system health and network diagnostics

Usage:
  netpulse scan [flags] <target>   run network diagnostics once and print the report
  netpulse serve [flags]           run the monitoring agent and dashboard
  netpulse <target>                shorthand for scan
  netpulse version                 print the version

Run "netpulse scan -h" or "netpulse serve -h" for each command's flags.
`)
}
