// Package cli turns command line arguments into engine options and renders the
// structured report. It holds all presentation logic so the engine stays usable
// from anything else later.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/probe"
)

// DefaultTarget keeps the V1 behaviour of scanning Google Public DNS when no
// target is given.
const DefaultTarget = "8.8.8.8"

// Run parses args, runs one scan and writes the report to stdout.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("net-pulse", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		portSpec    = fs.String("ports", "default", "ports to scan: \"default\", \"all\", or a list like 22,80,443,8000-8010")
		checkSpec   = fs.String("checks", "all", "checks to run: \"all\" or a list of dns,ports,tcp,tls,http")
		concurrency = fs.Int("concurrency", probe.DefaultConcurrency, "maximum simultaneous port connections")
		dialTimeout = fs.Duration("timeout", 2*time.Second, "TCP connect timeout per port")
		dnsTimeout  = fs.Duration("dns-timeout", 3*time.Second, "DNS lookup timeout")
		tlsTimeout  = fs.Duration("tls-timeout", 5*time.Second, "TLS handshake timeout")
		httpTimeout = fs.Duration("http-timeout", 10*time.Second, "HTTP request timeout")
		total       = fs.Duration("total-timeout", 60*time.Second, "overall budget for the whole scan")
		method      = fs.String("method", "GET", "HTTP method")
		follow      = fs.Bool("follow", true, "follow HTTP redirects")
		maxRedirect = fs.Int("max-redirects", 10, "maximum redirects to follow")
		asJSON      = fs.Bool("json", false, "print the structured report as JSON")
		showClosed  = fs.Bool("show-closed", false, "list closed and filtered ports too")
	)

	fs.Usage = func() {
		fmt.Fprintf(stderr, "net-pulse v2 - network diagnostics engine\n\n")
		fmt.Fprintf(stderr, "Usage:\n  net-pulse [flags] <target>\n\n")
		fmt.Fprintf(stderr, "Targets:\n")
		fmt.Fprintf(stderr, "  8.8.8.8            example.com            example.com:8443\n")
		fmt.Fprintf(stderr, "  https://example.com/health\n\n")
		fmt.Fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if fs.NArg() > 1 {
		return fmt.Errorf("expected one target, got %d", fs.NArg())
	}
	raw := DefaultTarget
	if fs.NArg() == 1 {
		raw = fs.Arg(0)
	}

	ports, err := probe.ParsePorts(*portSpec)
	if err != nil {
		return err
	}
	checks, err := parseChecks(*checkSpec)
	if err != nil {
		return err
	}
	if *concurrency <= 0 {
		return errors.New("concurrency must be at least 1")
	}

	opts := engine.Options{
		Checks:          checks,
		Ports:           ports,
		Concurrency:     *concurrency,
		DNSTimeout:      *dnsTimeout,
		DialTimeout:     *dialTimeout,
		TLSTimeout:      *tlsTimeout,
		HTTPTimeout:     *httpTimeout,
		TotalTimeout:    *total,
		HTTPMethod:      *method,
		FollowRedirects: *follow,
		MaxRedirects:    *maxRedirect,
	}

	report, err := engine.RunTarget(ctx, raw, opts)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	Render(stdout, report, *showClosed)
	return nil
}

func parseChecks(spec string) (engine.Checks, error) {
	trimmed := strings.ToLower(strings.TrimSpace(spec))
	if trimmed == "" || trimmed == "all" {
		return engine.All(), nil
	}

	var c engine.Checks
	for _, part := range strings.Split(trimmed, ",") {
		switch strings.TrimSpace(part) {
		case "":
			continue
		case "dns":
			c.DNS = true
		case "ports", "scan":
			c.Ports = true
		case "tcp":
			c.TCP = true
		case "tls":
			c.TLS = true
		case "http", "https":
			c.HTTP = true
		default:
			return c, fmt.Errorf("unknown check %q", part)
		}
	}
	if !c.Any() {
		return c, errors.New("no checks selected")
	}
	return c, nil
}
