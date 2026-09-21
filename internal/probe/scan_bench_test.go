package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// BenchmarkScanPorts measures the scanner against closed loopback ports, which
// isolates dial and scheduling overhead from real network latency. It is the
// benchmark worth keeping: it shows what the worker count actually buys.
func BenchmarkScanPorts(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		b.Fatalf("SplitHostPort: %v", err)
	}
	ln.Close()

	base, err := strconv.Atoi(portStr)
	if err != nil {
		b.Fatalf("Atoi: %v", err)
	}

	const numPorts = 64
	ports := make([]int, 0, numPorts)
	for i := 0; i < numPorts; i++ {
		ports = append(ports, base+i)
	}

	for _, workers := range []int{1, 8, 64} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			opts := ScanOptions{Concurrency: workers, Timeout: time.Second}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ScanPorts(context.Background(), "127.0.0.1", ports, opts)
			}
		})
	}
}
