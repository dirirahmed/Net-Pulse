package probe

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// DNSOptions configures a lookup.
type DNSOptions struct {
	Timeout     time.Duration
	Resolver    *net.Resolver
	LookupCNAME bool
}

// DNS resolves host and records how long it took and why it failed. An IP
// literal is reported as an immediate success so callers do not special-case it.
func DNS(ctx context.Context, host string, opts DNSOptions) result.DNSResult {
	res := result.DNSResult{Host: host}
	start := time.Now()

	if ip := net.ParseIP(host); ip != nil {
		res.Status = result.StatusOK
		res.Literal = true
		res.Addresses = []string{ip.String()}
		res.Primary = ip.String()
		res.Duration = result.Since(start)
		return res
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	addrs, err := resolver.LookupIPAddr(ctx, host)
	res.Duration = result.Since(start)
	if err != nil {
		res.Error = Classify(err)
		res.Status = statusForProbe(res.Error)
		return res
	}

	for _, a := range addrs {
		res.Addresses = append(res.Addresses, a.IP.String())
	}
	if len(res.Addresses) == 0 {
		res.Status = result.StatusError
		res.Error = &result.ProbeError{Kind: result.ErrKindDNS, Message: "lookup returned no addresses"}
		return res
	}

	res.Status = result.StatusOK
	res.Primary = PrimaryAddress(res.Addresses)

	if opts.LookupCNAME {
		if cname, cerr := resolver.LookupCNAME(ctx, host); cerr == nil {
			if !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(host, ".")) {
				res.CNAME = cname
			}
		}
	}
	return res
}
