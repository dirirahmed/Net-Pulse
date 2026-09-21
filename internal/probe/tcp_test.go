package probe

import (
	"context"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func TestTCPSuccess(t *testing.T) {
	addr := openListener(t)

	res := TCP(context.Background(), addr, TCPOptions{Timeout: 2 * time.Second})
	if res.Status != result.StatusOK {
		t.Fatalf("status = %q (%v), want ok", res.Status, res.Error)
	}
	if res.RemoteAddr == "" {
		t.Error("expected a remote address")
	}
	// A loopback connect can complete inside one clock tick on Windows, so zero
	// is a legitimate measurement here. Only a negative value is impossible.
	if res.Duration < 0 {
		t.Errorf("connect duration = %s, must not be negative", res.Duration)
	}
}

func TestTCPRefused(t *testing.T) {
	addr := closedAddress(t)

	res := TCP(context.Background(), addr, TCPOptions{Timeout: 2 * time.Second})
	if res.Status != result.StatusClosed {
		t.Fatalf("status = %q (%v), want closed", res.Status, res.Error)
	}
	if res.Error == nil {
		t.Fatal("expected a structured error")
	}
}

func TestTCPTimeout(t *testing.T) {
	addr := openListener(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // make sure the deadline has passed

	res := TCP(ctx, addr, TCPOptions{Timeout: 2 * time.Second})
	if res.Status != result.StatusTimeout {
		t.Fatalf("status = %q (%v), want timeout", res.Status, res.Error)
	}
	if res.Error == nil || res.Error.Kind != result.ErrKindTimeout {
		t.Fatalf("error = %v, want a timeout kind", res.Error)
	}
}
