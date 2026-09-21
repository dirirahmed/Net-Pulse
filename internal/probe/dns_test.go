package probe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func TestDNSIPLiteral(t *testing.T) {
	res := DNS(context.Background(), "127.0.0.1", DNSOptions{Timeout: time.Second})
	if res.Status != result.StatusOK {
		t.Fatalf("status = %q, want ok", res.Status)
	}
	if !res.Literal {
		t.Error("expected Literal to be true for an IP target")
	}
	if res.Primary != "127.0.0.1" {
		t.Errorf("primary = %q, want 127.0.0.1", res.Primary)
	}
	if res.Error != nil {
		t.Errorf("unexpected error: %v", res.Error)
	}
}

func TestDNSFailure(t *testing.T) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no nameserver reachable")
		},
	}

	res := DNS(context.Background(), "netpulse-does-not-exist.invalid", DNSOptions{
		Timeout:  2 * time.Second,
		Resolver: resolver,
	})

	if res.Status == result.StatusOK {
		t.Fatalf("expected a failure, got %+v", res)
	}
	if res.Error == nil {
		t.Fatal("expected a structured error")
	}
	if len(res.Addresses) != 0 {
		t.Errorf("expected no addresses, got %v", res.Addresses)
	}
}

func TestDNSTimeout(t *testing.T) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	start := time.Now()
	res := DNS(context.Background(), "netpulse-slow.invalid", DNSOptions{
		Timeout:  200 * time.Millisecond,
		Resolver: resolver,
	})
	elapsed := time.Since(start)

	// The exact error the Go resolver reports for an exhausted deadline varies
	// by platform, so assert that the probe failed and respected its budget.
	if res.Status != result.StatusTimeout && res.Status != result.StatusError {
		t.Fatalf("status = %q, want timeout or error", res.Status)
	}
	if res.Error == nil {
		t.Fatal("expected a structured error")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("lookup took %s, the timeout was not honoured", elapsed)
	}
}
