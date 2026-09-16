// Command netpulse is a concurrent TCP port scanner.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/report"
	"github.com/dirirahmed/Net-Pulse/internal/scanner"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		printUsage()
		return 2
	}
	args = args[1:]

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	portsFlag := fs.String("ports", "", "ports to scan: 80 / 22,80,443 / 1-1000 / 22,80,8000-8100 (default: common service registry)")
	workersFlag := fs.Int("workers", 100, "concurrent workers (1-5000)")
	timeoutFlag := fs.Duration("timeout", time.Second, "per-connection timeout (e.g. 500ms, 1s)")
	verboseFlag := fs.Bool("verbose", false, "show non-open results and error details")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: netpulse scan [flags] <target>")
		fs.PrintDefaults()
	}

	// flag.FlagSet stops parsing at the first positional argument, which
	// would break "netpulse scan 192.168.1.1 --verbose". Split flags out
	// from the target first so both orders work.
	flagArgs, positional := splitFlagsAndPositional(args, map[string]bool{
		"ports":   true,
		"workers": true,
		"timeout": true,
	})

	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if len(positional) == 0 {
		fmt.Fprintln(os.Stderr, "error: target is required")
		fs.Usage()
		return 2
	}
	if len(positional) > 1 {
		fmt.Fprintf(os.Stderr, "error: expected exactly one target, got %s\n", strings.Join(positional, ", "))
		return 2
	}
	target := positional[0]

	var ports []int
	var err error
	if *portsFlag == "" {
		ports = scanner.DefaultPorts()
	} else {
		ports, err = scanner.ParsePorts(*portsFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --ports: %v\n", err)
			return 2
		}
	}

	cfg, err := scanner.NewConfig(*workersFlag, *timeoutFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	host, err := scanner.ResolveTarget(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if host != target {
		fmt.Printf("netpulse: scanning %s (%s) - %d ports, %d workers, %s timeout\n", target, host, len(ports), cfg.Workers, cfg.Timeout)
	} else {
		fmt.Printf("netpulse: scanning %s - %d ports, %d workers, %s timeout\n", target, len(ports), cfg.Workers, cfg.Timeout)
	}

	results, scanErr := scanner.Scan(ctx, cfg, host, ports)

	report.WriteTable(os.Stdout, results, *verboseFlag)

	if errors.Is(scanErr, context.Canceled) {
		fmt.Fprintln(os.Stderr, "\nnetpulse: scan interrupted, showing partial results above")
		return 130
	}

	return 0
}

// splitFlagsAndPositional separates flag tokens from positional args so
// flags can appear before or after the target. valueFlags lists the flag
// names (no dashes) that consume a following token as their value; flags
// not in that set (bools, or anything using --flag=value) don't consume
// the next token.
func splitFlagsAndPositional(args []string, valueFlags map[string]bool) (flagArgs, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]

		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}

		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)

			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue // value is embedded, nothing more to consume
			}
			if valueFlags[name] && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}

		positional = append(positional, a)
	}
	return flagArgs, positional
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "netpulse - concurrent TCP port scanner")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "usage: netpulse scan [flags] <target>")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "examples:")
	fmt.Fprintln(os.Stderr, "  netpulse scan 127.0.0.1")
	fmt.Fprintln(os.Stderr, "  netpulse scan --ports 22,80,443 192.168.1.1")
	fmt.Fprintln(os.Stderr, "  netpulse scan --ports 1-1000 --workers 200 --timeout 500ms 192.168.1.1")
	fmt.Fprintln(os.Stderr, "  netpulse scan --verbose example.com")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "flags:")
	fmt.Fprintln(os.Stderr, "  --ports    ports to scan (default: common service registry)")
	fmt.Fprintln(os.Stderr, "  --workers  concurrent workers, 1-5000 (default 100)")
	fmt.Fprintln(os.Stderr, "  --timeout  per-connection timeout (default 1s)")
	fmt.Fprintln(os.Stderr, "  --verbose  show non-open results and error details")
}
