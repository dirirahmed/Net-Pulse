package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/model"
)

// fakeConn is a minimal net.Conn for tests/benchmarks that don't need real
// networking - just something dial functions can return.
type fakeConn struct{}

func (fakeConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (fakeConn) Close() error                       { return nil }
func (fakeConn) LocalAddr() net.Addr                { return nil }
func (fakeConn) RemoteAddr() net.Addr               { return nil }
func (fakeConn) SetDeadline(t time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// fixedDelayDialer returns a dialFunc that waits `delay` then succeeds,
// unless the context gets cancelled first. Used to get deterministic
// timing behavior in tests/benchmarks instead of relying on real sockets.
func fixedDelayDialer(delay time.Duration) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case <-time.After(delay):
			return fakeConn{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func TestProbeOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := mustAtoi(t, portStr)

	dial := (&net.Dialer{}).DialContext
	res := probe(context.Background(), dial, host, port, time.Second)

	if res.State != model.StateOpen {
		t.Fatalf("state = %s, want OPEN", res.State)
	}
	if res.Latency < 0 {
		t.Errorf("latency = %v, want >= 0", res.Latency)
	}
	if res.Port != port {
		t.Errorf("port = %d, want %d", res.Port, port)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	// Bind then immediately close - the OS should refuse connections to
	// this port for a while afterward on most systems.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := mustAtoi(t, portStr)
	ln.Close()

	dial := (&net.Dialer{}).DialContext
	res := probe(context.Background(), dial, host, port, time.Second)

	if res.State != model.StateClosed {
		t.Fatalf("state = %s, want CLOSED (err=%s)", res.State, res.ErrType)
	}
	if res.ErrType != model.ErrConnectionRefused {
		t.Fatalf("errType = %s, want CONNECTION_REFUSED", res.ErrType)
	}
	if res.Latency != 0 {
		t.Errorf("latency = %v, want 0 for non-open result", res.Latency)
	}
}

func TestProbeTimeout(t *testing.T) {
	// Real network timeouts are flaky in CI, so use an injected dialer
	// that's guaranteed to outlast the configured timeout.
	dial := fixedDelayDialer(200 * time.Millisecond)
	res := probe(context.Background(), dial, "127.0.0.1", 9999, 10*time.Millisecond)

	if res.State != model.StateTimeout {
		t.Fatalf("state = %s, want TIMEOUT", res.State)
	}
	if res.ErrType != model.ErrTimeout {
		t.Fatalf("errType = %s, want TIMEOUT", res.ErrType)
	}
	if res.Latency != 0 {
		t.Errorf("latency = %v, want 0 on timeout", res.Latency)
	}
}

func TestProbeNeverReportsTimeoutAsFiltered(t *testing.T) {
	dial := fixedDelayDialer(200 * time.Millisecond)
	res := probe(context.Background(), dial, "127.0.0.1", 9999, 10*time.Millisecond)

	if res.State.String() == "FILTERED" || res.ErrType.String() == "FILTERED" {
		t.Fatal("a timeout must never be reported as FILTERED")
	}
}

func TestProbeSuccessClosesConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port := mustAtoi(t, portStr)

	dial := (&net.Dialer{}).DialContext
	res := probe(context.Background(), dial, host, port, time.Second)
	if res.State != model.StateOpen {
		t.Fatalf("state = %s, want OPEN", res.State)
	}

	select {
	case c := <-accepted:
		defer c.Close()
		// Give the client side a moment to actually close, then confirm
		// the server sees EOF instead of the connection hanging open.
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1)
		_, err := c.Read(buf)
		if !errors.Is(err, io.EOF) {
			t.Errorf("expected EOF after client close, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server never accepted connection")
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a valid port string: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func TestNewConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		workers int
		timeout time.Duration
		wantErr bool
	}{
		{"valid", 100, time.Second, false},
		{"min workers", 1, time.Second, false},
		{"max workers", 5000, time.Second, false},
		{"zero workers", 0, time.Second, true},
		{"too many workers", 5001, time.Second, true},
		{"negative workers", -1, time.Second, true},
		{"zero timeout", 100, 0, true},
		{"negative timeout", 100, -time.Second, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewConfig(tt.workers, tt.timeout)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
