package probe

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func TestScanPortsOpenAndClosed(t *testing.T) {
	openPort := portOf(t, openListener(t))
	closedPort := portOf(t, closedAddress(t))

	res := ScanPorts(context.Background(), "127.0.0.1", []int{openPort, closedPort}, ScanOptions{
		Concurrency: 2,
		Timeout:     2 * time.Second,
	})

	if len(res.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(res.Results))
	}
	if res.Results[0].Status != result.StatusOpen {
		t.Errorf("open port status = %q (%v)", res.Results[0].Status, res.Results[0].Error)
	}
	if res.Results[1].Status != result.StatusClosed {
		t.Errorf("closed port status = %q (%v)", res.Results[1].Status, res.Results[1].Error)
	}
	if res.Open != 1 {
		t.Errorf("Open = %d, want 1", res.Open)
	}
	if res.Scanned != 2 {
		t.Errorf("Scanned = %d, want 2", res.Scanned)
	}
	if len(res.OpenPorts()) != 1 {
		t.Errorf("OpenPorts returned %d entries, want 1", len(res.OpenPorts()))
	}
}

func TestScanPortsKeepsOrdering(t *testing.T) {
	ports := []int{9001, 9002, 9003, 9004, 9005}
	res := ScanPorts(context.Background(), "127.0.0.1", ports, ScanOptions{
		Concurrency: 5,
		Timeout:     500 * time.Millisecond,
	})
	for i, r := range res.Results {
		if r.Port != ports[i] {
			t.Fatalf("result %d has port %d, want %d", i, r.Port, ports[i])
		}
	}
}

// TestScanPortsBoundedConcurrency is the guard against V1's goroutine-per-port
// behaviour: with N workers, no more than N dials may ever be in flight.
func TestScanPortsBoundedConcurrency(t *testing.T) {
	const (
		workers  = 4
		numPorts = 40
	)

	var inFlight int64
	var maxInFlight int64

	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			current := atomic.AddInt64(&inFlight, 1)
			for {
				peak := atomic.LoadInt64(&maxInFlight)
				if current <= peak || atomic.CompareAndSwapInt64(&maxInFlight, peak, current) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			atomic.AddInt64(&inFlight, -1)
			return nil
		},
	}

	base := portOf(t, closedAddress(t))
	ports := make([]int, 0, numPorts)
	for i := 0; i < numPorts; i++ {
		ports = append(ports, base+i)
	}

	res := ScanPorts(context.Background(), "127.0.0.1", ports, ScanOptions{
		Concurrency: workers,
		Timeout:     2 * time.Second,
		Dialer:      dialer,
	})

	if len(res.Results) != numPorts {
		t.Fatalf("got %d results, want %d", len(res.Results), numPorts)
	}
	if peak := atomic.LoadInt64(&maxInFlight); peak > workers {
		t.Fatalf("peak concurrency was %d, want at most %d", peak, workers)
	}
}

func TestScanPortsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ports := []int{9101, 9102, 9103, 9104}
	res := ScanPorts(ctx, "127.0.0.1", ports, ScanOptions{Concurrency: 2, Timeout: time.Second})

	if len(res.Results) != len(ports) {
		t.Fatalf("got %d results, want %d", len(res.Results), len(ports))
	}
	for i, r := range res.Results {
		if r.Status == "" {
			t.Fatalf("result %d has no status", i)
		}
		if r.Status == result.StatusOpen {
			t.Fatalf("result %d unexpectedly open", i)
		}
		if r.Port != ports[i] {
			t.Fatalf("result %d has port %d, want %d", i, r.Port, ports[i])
		}
	}
}

func TestScanPortsEmpty(t *testing.T) {
	res := ScanPorts(context.Background(), "127.0.0.1", nil, ScanOptions{})
	if len(res.Results) != 0 || res.Scanned != 0 {
		t.Fatalf("unexpected result for an empty port list: %+v", res)
	}
}
