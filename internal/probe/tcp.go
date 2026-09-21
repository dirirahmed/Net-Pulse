package probe

import (
	"context"
	"net"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// TCPOptions configures a connection attempt.
type TCPOptions struct {
	Timeout time.Duration
	Dialer  *net.Dialer
}

// TCP opens and immediately closes a connection, recording how long the
// handshake took and how it failed.
func TCP(ctx context.Context, address string, opts TCPOptions) result.TCPResult {
	res := result.TCPResult{Address: address, Timeout: result.Duration(opts.Timeout)}

	start := time.Now()
	conn, err := dial(ctx, address, opts.Timeout, opts.Dialer)
	res.Duration = result.Since(start)
	if err != nil {
		res.Error = Classify(err)
		res.Status = statusForConnect(res.Error)
		return res
	}
	defer conn.Close()

	res.LocalAddr = conn.LocalAddr().String()
	res.RemoteAddr = conn.RemoteAddr().String()
	res.Status = result.StatusOK
	return res
}

// dial is the single place where connections are created, so every probe gets
// the same timeout and cancellation behaviour.
func dial(ctx context.Context, address string, timeout time.Duration, base *net.Dialer) (net.Conn, error) {
	var d net.Dialer
	if base != nil {
		d = *base
	}
	if timeout > 0 {
		d.Timeout = timeout
	}
	return d.DialContext(ctx, "tcp", address)
}
