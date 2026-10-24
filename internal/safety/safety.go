// Package safety decides which targets are allowed to be scanned.
//
// The CLI assumes you own the target, so it does no checking. Anything that
// accepts a target from someone else cannot make that assumption: a submitted
// hostname could point at the machine running the scan, the private network
// around it, or a cloud metadata endpoint.
//
// Two checks, because neither is sufficient alone:
//
//   - CheckTarget resolves the hostname up front and rejects it if any answer
//     is a reserved address. This gives a clear error before a scan starts.
//
//   - Dialer re-checks at connect time, inside net.Dialer.Control, which runs
//     after resolution with the address the kernel is about to connect to.
//     This is the one that actually holds: it sees a name that resolves
//     differently the second time (DNS rebinding) and redirects pointing at
//     internal hosts, neither of which the up-front check can catch.
package safety

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// BlockedError means a target was refused by policy rather than being invalid.
type BlockedError struct {
	Target string
	Reason string
}

func (e *BlockedError) Error() string {
	if e.Target == "" {
		return "target is not scannable: " + e.Reason
	}
	return fmt.Sprintf("%s is not scannable: %s", e.Target, e.Reason)
}

// Guard performs the checks. The zero value blocks private addresses;
// AllowPrivate turns the checks off for local development and for tests that
// scan a loopback server.
type Guard struct {
	AllowPrivate bool

	// ResolveTimeout bounds the up-front lookup. Zero means three seconds.
	ResolveTimeout time.Duration

	// Resolver overrides the system resolver. Tests use it.
	Resolver *net.Resolver
}

// CheckTarget resolves host and rejects it if it is reserved.
//
// A host is refused if *any* of its addresses is reserved, not only if all of
// them are. A name answering with one public and one private address is either
// a rebinding attempt or a misconfiguration, and neither is worth scanning.
func (g *Guard) CheckTarget(ctx context.Context, host string) error {
	if g.AllowPrivate {
		return nil
	}

	if reason, blocked := BlockedHostname(host); blocked {
		return &BlockedError{Target: host, Reason: reason}
	}

	if ip := net.ParseIP(host); ip != nil {
		if reason, blocked := BlockedIP(ip); blocked {
			return &BlockedError{Target: host, Reason: reason}
		}
		return nil
	}

	timeout := g.ResolveTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := g.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	addrs, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("could not resolve %s", host)
	}
	for _, a := range addrs {
		if reason, blocked := BlockedIP(a.IP); blocked {
			return &BlockedError{
				Target: host,
				Reason: fmt.Sprintf("it resolves to %s, %s", a.IP, reason),
			}
		}
	}
	return nil
}

// Dialer returns a dialer that refuses to connect to reserved addresses.
//
// Every probe in the engine dials through whatever dialer it is handed, so
// passing this one into engine.Options covers ports, TCP, TLS and HTTP at once
// rather than leaving each call site to remember.
func (g *Guard) Dialer() *net.Dialer {
	if g.AllowPrivate {
		return &net.Dialer{}
	}
	return &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return &BlockedError{Target: address, Reason: "the address could not be parsed"}
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return &BlockedError{Target: address, Reason: "the address is not a literal IP"}
			}
			if reason, blocked := BlockedIP(ip); blocked {
				return &BlockedError{Target: ip.String(), Reason: reason}
			}
			return nil
		},
	}
}

// blockedCIDRs is a deny-list rather than an allow-list of public space. A gap
// in an allow-list only breaks legitimate scans; a gap in a deny-list exposes
// internal hosts, so this list is kept deliberately broad.
var blockedCIDRs = []struct{ cidr, reason string }{
	{"0.0.0.0/8", "it is an unspecified address"},
	{"10.0.0.0/8", "it is a private network (RFC 1918)"},
	{"100.64.0.0/10", "it is carrier-grade NAT space"},
	{"127.0.0.0/8", "it is a loopback address"},
	{"169.254.0.0/16", "it is link-local, which includes cloud metadata endpoints"},
	{"172.16.0.0/12", "it is a private network (RFC 1918)"},
	{"192.0.0.0/24", "it is IETF protocol assignment space"},
	{"192.0.2.0/24", "it is documentation space"},
	{"192.168.0.0/16", "it is a private network (RFC 1918)"},
	{"198.18.0.0/15", "it is benchmarking space"},
	{"198.51.100.0/24", "it is documentation space"},
	{"203.0.113.0/24", "it is documentation space"},
	{"224.0.0.0/4", "it is a multicast address"},
	{"240.0.0.0/4", "it is reserved space"},

	{"::/128", "it is an unspecified address"},
	{"::1/128", "it is a loopback address"},
	{"64:ff9b::/96", "it is NAT64 space, which can embed a private IPv4 address"},
	{"2001:db8::/32", "it is documentation space"},
	{"fc00::/7", "it is a unique local address"},
	{"fe80::/10", "it is a link-local address"},
	{"ff00::/8", "it is a multicast address"},
}

var (
	blockedNets    []*net.IPNet
	blockedReasons []string
)

func init() {
	for _, entry := range blockedCIDRs {
		_, network, err := net.ParseCIDR(entry.cidr)
		if err != nil {
			panic("safety: bad CIDR in blocklist: " + entry.cidr)
		}
		blockedNets = append(blockedNets, network)
		blockedReasons = append(blockedReasons, entry.reason)
	}
}

// BlockedIP reports whether an address is reserved, and why.
func BlockedIP(ip net.IP) (string, bool) {
	if ip == nil {
		return "the address could not be parsed", true
	}
	// ::ffff:127.0.0.1 reaches loopback, so judge mapped addresses as IPv4.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for i, network := range blockedNets {
		if network.Contains(ip) {
			return blockedReasons[i], true
		}
	}
	return "", false
}

var blockedSuffixes = []string{
	".localhost", ".local", ".internal", ".home.arpa", ".lan", ".localdomain",
}

var blockedNames = map[string]bool{
	"localhost":     true,
	"ip6-localhost": true,
	"ip6-loopback":  true,
	"broadcasthost": true,
	"metadata":      true,
}

// BlockedHostname reports whether a name is reserved for local use. These are
// caught before any lookup, so a misconfigured resolver cannot be used to
// reach them.
func BlockedHostname(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return "the hostname is empty", true
	}
	if blockedNames[h] {
		return "it is a reserved local hostname", true
	}
	for _, suffix := range blockedSuffixes {
		if strings.HasSuffix(h, suffix) {
			return "it ends in the reserved suffix " + suffix, true
		}
	}
	return "", false
}
