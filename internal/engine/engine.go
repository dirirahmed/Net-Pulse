package engine

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/probe"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// Checks selects which diagnostics to run.
type Checks struct {
	DNS   bool
	Ports bool
	TCP   bool
	TLS   bool
	HTTP  bool
}

// All enables every diagnostic.
func All() Checks {
	return Checks{DNS: true, Ports: true, TCP: true, TLS: true, HTTP: true}
}

// Any reports whether at least one check is enabled.
func (c Checks) Any() bool {
	return c.DNS || c.Ports || c.TCP || c.TLS || c.HTTP
}

// Options configures a scan.
type Options struct {
	Checks      Checks
	Ports       []int
	Concurrency int

	DNSTimeout   time.Duration
	DialTimeout  time.Duration
	TLSTimeout   time.Duration
	HTTPTimeout  time.Duration
	TotalTimeout time.Duration

	HTTPMethod      string
	UserAgent       string
	FollowRedirects bool
	MaxRedirects    int

	// RootCAs overrides the system trust store. Tests use it; production runs
	// leave it nil so real verification applies.
	RootCAs *x509.CertPool

	// Dialer, when set, is used for every outbound connection this scan makes.
	// A caller that does not control the target supplies one whose Control
	// hook refuses private addresses, which is what covers DNS rebinding and
	// redirects to internal hosts. The engine attaches no policy of its own.
	Dialer *net.Dialer
}

// DefaultOptions returns sensible defaults for interactive use.
func DefaultOptions() Options {
	return Options{
		Checks:          All(),
		Ports:           probe.DefaultPorts(),
		Concurrency:     probe.DefaultConcurrency,
		DNSTimeout:      3 * time.Second,
		DialTimeout:     2 * time.Second,
		TLSTimeout:      5 * time.Second,
		HTTPTimeout:     10 * time.Second,
		TotalTimeout:    60 * time.Second,
		HTTPMethod:      "GET",
		UserAgent:       probe.DefaultUserAgent,
		FollowRedirects: true,
		MaxRedirects:    10,
	}
}

func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if !o.Checks.Any() {
		o.Checks = d.Checks
	}
	if len(o.Ports) == 0 {
		o.Ports = d.Ports
	}
	if o.Concurrency <= 0 {
		o.Concurrency = d.Concurrency
	}
	if o.DNSTimeout <= 0 {
		o.DNSTimeout = d.DNSTimeout
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = d.DialTimeout
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = d.TLSTimeout
	}
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = d.HTTPTimeout
	}
	if o.HTTPMethod == "" {
		o.HTTPMethod = d.HTTPMethod
	}
	if o.UserAgent == "" {
		o.UserAgent = d.UserAgent
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = d.MaxRedirects
	}
	return o
}

// tlsPorts are the ports we assume speak TLS when no scheme was given.
var tlsPorts = map[int]bool{443: true, 8443: true, 9443: true}

// httpPorts are the ports we assume speak HTTP when no scheme was given.
var httpPorts = map[int]bool{80: true, 443: true, 8080: true, 8443: true, 9443: true}

// Run executes the selected diagnostics against one target and returns a single
// structured report. It never returns an error: failures belong in the report.
func Run(ctx context.Context, target result.Target, opts Options) result.Report {
	opts = opts.withDefaults()

	rep := result.Report{Target: target, StartedAt: time.Now()}
	start := time.Now()

	if opts.TotalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.TotalTimeout)
		defer cancel()
	}

	// dialHost is what we connect to; target.Host stays the name used for SNI,
	// the Host header and certificate verification.
	dialHost := target.Host
	resolvable := true

	if opts.Checks.DNS {
		dns := probe.DNS(ctx, target.Host, probe.DNSOptions{
			Timeout:     opts.DNSTimeout,
			LookupCNAME: !target.IsIP,
		})
		if dns.Status == result.StatusOK && dns.Primary != "" {
			dialHost = dns.Primary
		} else if dns.Status != result.StatusOK {
			resolvable = false
		}
		rep.DNS = &dns
	}

	if !resolvable {
		rep.Notes = append(rep.Notes, "skipped tcp/tls/http/port checks: DNS resolution failed")
		rep.Duration = result.Since(start)
		return rep
	}

	port := primaryPort(target)

	if opts.Checks.Ports {
		scan := probe.ScanPorts(ctx, dialHost, opts.Ports, probe.ScanOptions{
			Concurrency: opts.Concurrency,
			Timeout:     opts.DialTimeout,
			Dialer:      opts.Dialer,
		})
		scan.Host = target.Host
		scan.Address = dialHost
		rep.Ports = &scan
	}

	if opts.Checks.TCP {
		tcp := probe.TCP(ctx, net.JoinHostPort(dialHost, strconv.Itoa(port)), probe.TCPOptions{
			Timeout: opts.DialTimeout,
			Dialer:  opts.Dialer,
		})
		rep.TCP = &tcp
	}

	useTLS := usesTLS(target, port)
	if opts.Checks.TLS {
		if !useTLS {
			rep.Notes = append(rep.Notes, fmt.Sprintf("skipped tls check: port %d is not treated as a TLS port", port))
		} else {
			tlsRes := probe.TLSHandshake(ctx, net.JoinHostPort(dialHost, strconv.Itoa(port)), probe.TLSOptions{
				Timeout:                opts.TLSTimeout,
				ServerName:             target.Host,
				RootCAs:                opts.RootCAs,
				Dialer:                 opts.Dialer,
				NextProtos:             []string{"h2", "http/1.1"},
				CollectOnVerifyFailure: true,
			})
			rep.TLS = &tlsRes
		}
	}

	if opts.Checks.HTTP {
		if !usesHTTP(target, port) {
			rep.Notes = append(rep.Notes, fmt.Sprintf("skipped http check: port %d is not treated as an HTTP port", port))
		} else {
			httpRes := probe.HTTP(ctx, buildURL(target, port, useTLS), probe.HTTPOptions{
				Method:          opts.HTTPMethod,
				Timeout:         opts.HTTPTimeout,
				FollowRedirects: opts.FollowRedirects,
				MaxRedirects:    opts.MaxRedirects,
				UserAgent:       opts.UserAgent,
				RootCAs:         opts.RootCAs,
				Dialer:          opts.Dialer,
			})
			rep.HTTP = &httpRes
		}
	}

	rep.Duration = result.Since(start)
	return rep
}

// RunTarget parses raw and runs the scan.
func RunTarget(ctx context.Context, raw string, opts Options) (result.Report, error) {
	target, err := ParseTarget(raw)
	if err != nil {
		return result.Report{}, err
	}
	return Run(ctx, target, opts), nil
}

func primaryPort(t result.Target) int {
	if t.Port != 0 {
		return t.Port
	}
	if t.Scheme == "http" {
		return 80
	}
	return 443
}

func usesTLS(t result.Target, port int) bool {
	switch t.Scheme {
	case "https":
		return true
	case "http":
		return false
	}
	return tlsPorts[port]
}

func usesHTTP(t result.Target, port int) bool {
	if t.Scheme == "http" || t.Scheme == "https" {
		return true
	}
	return httpPorts[port]
}

func buildURL(t result.Target, port int, useTLS bool) string {
	scheme := t.Scheme
	if scheme == "" {
		if useTLS {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := t.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if !isDefaultPort(scheme, port) {
		host = host + ":" + strconv.Itoa(port)
	}

	path := t.Path
	if path == "" {
		path = "/"
	}

	u := url.URL{Scheme: scheme, Host: host, Path: path}
	return u.String()
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}
