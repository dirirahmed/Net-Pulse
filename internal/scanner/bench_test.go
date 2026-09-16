package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// openListeners starts n real TCP listeners on 127.0.0.1 and accepts (and
// immediately closes) whatever connects. Returns their ports and a cleanup
// func.
func openListeners(tb testing.TB, n int) (ports []int, cleanup func()) {
	tb.Helper()
	listeners := make([]net.Listener, 0, n)
	ports = make([]int, 0, n)

	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			tb.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)

		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.Atoi(portStr)
		ports = append(ports, p)

		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}(ln)
	}

	return ports, func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}
}

// closedPorts grabs n ports by briefly listening on them, then closes the
// listeners right away so connecting to them gets refused.
func closedPorts(tb testing.TB, n int) []int {
	tb.Helper()
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			tb.Fatalf("listen: %v", err)
		}
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.Atoi(portStr)
		ports = append(ports, p)
		ln.Close()
	}
	return ports
}

// benchPorts gives a fixed mix of open + closed local ports for the
// benchmarks below to scan against.
func benchPorts(tb testing.TB) (ports []int, cleanup func()) {
	open, cleanup := openListeners(tb, 20)
	closed := closedPorts(tb, 20)
	return append(open, closed...), cleanup
}

// BenchmarkSequentialScan probes every port one at a time, no worker pool -
// this is the baseline the worker pool is meant to beat.
func BenchmarkSequentialScan(b *testing.B) {
	ports, cleanup := benchPorts(b)
	defer cleanup()

	dial := (&net.Dialer{}).DialContext

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range ports {
			probe(context.Background(), dial, "127.0.0.1", p, 200*time.Millisecond)
		}
	}
}

// BenchmarkWorkerPoolScan runs the same port set through the real worker
// pool at different worker counts, against real local listeners.
func BenchmarkWorkerPoolScan(b *testing.B) {
	ports, cleanup := benchPorts(b)
	defer cleanup()

	for _, workers := range []int{1, 5, 10, 25, 50, 100, 250} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			cfg, err := NewConfig(workers, 200*time.Millisecond)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Scan(context.Background(), cfg, "127.0.0.1", ports); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkWorkerPoolScanSyntheticDelay uses an injected fixed-delay dialer
// instead of real sockets, so the pool's concurrency behavior can be
// measured deterministically - no OS scheduling/network noise involved.
func BenchmarkWorkerPoolScanSyntheticDelay(b *testing.B) {
	const delay = 2 * time.Millisecond
	const numPorts = 200

	ports := make([]int, numPorts)
	for i := range ports {
		ports[i] = i + 1
	}

	for _, workers := range []int{1, 5, 10, 25, 50, 100, 250} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			cfg, err := NewConfig(workers, time.Second)
			if err != nil {
				b.Fatal(err)
			}
			cfg.dial = fixedDelayDialer(delay)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Scan(context.Background(), cfg, "127.0.0.1", ports); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
