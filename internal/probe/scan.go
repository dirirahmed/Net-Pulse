package probe

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// DefaultConcurrency is the worker count used when none is configured.
const DefaultConcurrency = 100

// ScanOptions configures a port scan.
type ScanOptions struct {
	Concurrency int
	Timeout     time.Duration
	Dialer      *net.Dialer
}

// ScanPorts probes every port with a fixed worker pool. The number of
// goroutines never exceeds Concurrency regardless of how many ports are given,
// which is the main change from V1's goroutine-per-port approach.
func ScanPorts(ctx context.Context, host string, ports []int, opts ScanOptions) result.PortScanResult {
	res := result.PortScanResult{Host: host, Scanned: len(ports)}
	start := time.Now()
	if len(ports) == 0 {
		res.Duration = result.Since(start)
		return res
	}

	workers := opts.Concurrency
	if workers <= 0 {
		workers = DefaultConcurrency
	}
	if workers > len(ports) {
		workers = len(ports)
	}

	// Each worker writes to its own index, so no lock is needed and the results
	// keep the caller's port ordering.
	results := make([]result.PortResult, len(ports))
	jobs := make(chan int)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = probePort(ctx, host, ports[i], opts)
			}
		}()
	}

feed:
	for i := range ports {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	for i := range results {
		if results[i].Status == "" {
			results[i] = result.PortResult{
				Port:    ports[i],
				Service: ServiceName(ports[i]),
				Status:  result.StatusSkipped,
				Error:   &result.ProbeError{Kind: result.ErrKindCanceled, Message: "scan stopped before this port was probed"},
			}
			continue
		}
		if results[i].IsOpen() {
			res.Open++
		}
	}

	res.Results = results
	res.Duration = result.Since(start)
	return res
}

func probePort(ctx context.Context, host string, port int, opts ScanOptions) result.PortResult {
	pr := result.PortResult{Port: port, Service: ServiceName(port)}
	address := net.JoinHostPort(host, strconv.Itoa(port))

	start := time.Now()
	conn, err := dial(ctx, address, opts.Timeout, opts.Dialer)
	pr.Duration = result.Since(start)
	if err != nil {
		pr.Error = Classify(err)
		pr.Status = statusForConnect(pr.Error)
		return pr
	}
	conn.Close()
	pr.Status = result.StatusOpen
	return pr
}
