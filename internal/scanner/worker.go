package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/dirirahmed/Net-Pulse/internal/model"
)

// ResolveTarget resolves target (hostname or IP) to a single IP address to
// scan. This happens once per scan, not once per port - DNS lookup time is
// not part of per-port connect latency.
func ResolveTarget(ctx context.Context, target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, target)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", target, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses found for %s", target)
	}

	// Prefer IPv4 when we have a choice.
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP.String(), nil
		}
	}
	return addrs[0].IP.String(), nil
}

// Scan runs a bounded worker pool over ports against host. Results come
// back sorted by port.
//
// producer -> jobs chan -> N workers -> results chan -> aggregator (here)
//
// If ctx is cancelled partway through, the producer stops handing out new
// ports, workers stop, and whatever results were already collected are
// still returned - along with ctx.Err() so the caller knows the scan was
// cut short.
func Scan(ctx context.Context, cfg *Config, host string, ports []int) ([]model.Result, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}

	workers := cfg.Workers
	if workers > len(ports) {
		workers = len(ports)
	}

	jobs := make(chan int)
	results := make(chan model.Result)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for port := range jobs {
				res := probe(ctx, cfg.dial, host, port, cfg.Timeout)
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case jobs <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]model.Result, 0, len(ports))
	for res := range results {
		out = append(out, res)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out, ctx.Err()
}
