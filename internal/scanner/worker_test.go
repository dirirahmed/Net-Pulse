package scanner

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/model"
)

func TestScanResultsSortedByPort(t *testing.T) {
	cfg, err := NewConfig(10, time.Second)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	cfg.dial = fixedDelayDialer(0)

	ports := []int{300, 100, 200, 50, 400}
	results, err := Scan(context.Background(), cfg, "127.0.0.1", ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(results) != len(ports) {
		t.Fatalf("got %d results, want %d", len(results), len(ports))
	}
	for i := 1; i < len(results); i++ {
		if results[i-1].Port >= results[i].Port {
			t.Fatalf("results not sorted: %v", results)
		}
	}
}

func TestScanNeverExceedsPortCount(t *testing.T) {
	// workers > ports shouldn't spawn more goroutines than there is work.
	// Can't observe goroutine count directly per-job, but we can at least
	// confirm the scan completes correctly and doesn't hang or double up.
	cfg, err := NewConfig(5000, time.Second)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	cfg.dial = fixedDelayDialer(0)

	results, err := Scan(context.Background(), cfg, "127.0.0.1", []int{1, 2, 3})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
}

func TestScanWorkerPoolIsBounded(t *testing.T) {
	const delay = 50 * time.Millisecond
	const numPorts = 10

	ports := make([]int, numPorts)
	for i := range ports {
		ports[i] = i + 1
	}

	// With only 2 workers and 10 ports each taking `delay`, work happens
	// in ~5 serialized rounds - this should take noticeably longer than
	// a single delay, proving concurrency is actually bounded and not
	// one-goroutine-per-port.
	cfg, _ := NewConfig(2, time.Second)
	cfg.dial = fixedDelayDialer(delay)

	start := time.Now()
	_, err := Scan(context.Background(), cfg, "127.0.0.1", ports)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if elapsed < 3*delay {
		t.Errorf("bounded pool finished too fast (%v) - expected serialization with only 2 workers", elapsed)
	}
}

func TestScanWorkerPoolParallelizes(t *testing.T) {
	const delay = 50 * time.Millisecond
	const numPorts = 20

	ports := make([]int, numPorts)
	for i := range ports {
		ports[i] = i + 1
	}

	// Plenty of workers for the port count - should all run ~concurrently,
	// finishing close to a single delay instead of numPorts*delay.
	cfg, _ := NewConfig(100, time.Second)
	cfg.dial = fixedDelayDialer(delay)

	start := time.Now()
	_, err := Scan(context.Background(), cfg, "127.0.0.1", ports)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if elapsed > 5*delay {
		t.Errorf("fully parallel scan took %v, expected close to %v", elapsed, delay)
	}
}

func TestScanCancellation(t *testing.T) {
	ports := make([]int, 200)
	for i := range ports {
		ports[i] = i + 1
	}

	cfg, _ := NewConfig(4, time.Second)
	cfg.dial = fixedDelayDialer(500 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	results, err := Scan(ctx, cfg, "127.0.0.1", ports)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// Should stop well before all 200 ports * 500ms would've taken.
	if elapsed > 2*time.Second {
		t.Errorf("cancellation took too long to take effect: %v", elapsed)
	}
	t.Logf("collected %d/%d results before cancellation", len(results), len(ports))
}

func TestScanGoroutineCleanup(t *testing.T) {
	baseline := goroutineCountSettled(t)

	ports := make([]int, 50)
	for i := range ports {
		ports[i] = i + 1
	}
	cfg, _ := NewConfig(10, time.Second)
	cfg.dial = fixedDelayDialer(5 * time.Millisecond)

	// Run a normal scan and a cancelled scan - both should clean up.
	if _, err := Scan(context.Background(), cfg, "127.0.0.1", ports); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cfg.dial = fixedDelayDialer(500 * time.Millisecond)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, _ = Scan(ctx, cfg, "127.0.0.1", ports)

	after := goroutineCountSettled(t)
	if after > baseline+2 {
		t.Errorf("possible goroutine leak: baseline=%d, after=%d", baseline, after)
	}
}

// goroutineCountSettled polls runtime.NumGoroutine until it stabilizes
// (stops dropping), giving background goroutines from prior work time to
// actually exit before we sample the "settled" count.
func goroutineCountSettled(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	last := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		cur := runtime.NumGoroutine()
		if cur == last {
			return cur
		}
		last = cur
	}
	return last
}

func TestResolveTargetIPPassthrough(t *testing.T) {
	got, err := ResolveTarget(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if got != "127.0.0.1" {
		t.Errorf("got %q, want 127.0.0.1", got)
	}
}

func TestResolveTargetHostname(t *testing.T) {
	got, err := ResolveTarget(context.Background(), "localhost")
	if err != nil {
		t.Skipf("localhost did not resolve in this environment: %v", err)
	}
	if net.ParseIP(got) == nil {
		t.Errorf("ResolveTarget(localhost) = %q, not a valid IP", got)
	}
}

func TestResolveTargetBadHostname(t *testing.T) {
	_, err := ResolveTarget(context.Background(), "this-host-should-not-exist.invalid")
	if err == nil {
		t.Fatal("expected error resolving a bogus hostname, got nil")
	}
}

func TestScanEmptyPortsErrors(t *testing.T) {
	cfg, _ := NewConfig(10, time.Second)
	_, err := Scan(context.Background(), cfg, "127.0.0.1", nil)
	if err == nil {
		t.Fatal("expected error for empty port list")
	}
}

func TestScanErrorResultsClassified(t *testing.T) {
	cfg, _ := NewConfig(4, 20*time.Millisecond)
	cfg.dial = fixedDelayDialer(200 * time.Millisecond)

	results, err := Scan(context.Background(), cfg, "127.0.0.1", []int{1, 2, 3})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, r := range results {
		if r.State != model.StateTimeout {
			t.Errorf("port %d: state = %s, want TIMEOUT", r.Port, r.State)
		}
	}
}
