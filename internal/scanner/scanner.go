package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/model"
)

// dialFunc matches net.Dialer.DialContext. It's a field on Config instead of
// an interface so tests can swap in a fake dialer without needing mocks.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config holds the knobs for a scan.
type Config struct {
	Workers int
	Timeout time.Duration

	dial dialFunc
}

// NewConfig builds a Config, validating workers and timeout.
func NewConfig(workers int, timeout time.Duration) (*Config, error) {
	if workers < 1 || workers > 5000 {
		return nil, fmt.Errorf("workers must be between 1 and 5000, got %d", workers)
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than 0, got %s", timeout)
	}
	return &Config{
		Workers: workers,
		Timeout: timeout,
		dial:    (&net.Dialer{}).DialContext,
	}, nil
}

// probe dials a single host:port and turns the outcome into a model.Result.
// Latency is only measured for successful connections - DNS resolution
// should already have happened before this is called, so it's not part of
// this timing.
func probe(ctx context.Context, dial dialFunc, host string, port int, timeout time.Duration) model.Result {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := model.Result{
		Address: address,
		Port:    port,
		Service: ServiceHint(port),
	}

	start := time.Now()
	conn, err := dial(dialCtx, "tcp", address)
	if err != nil {
		res.State, res.ErrType = classifyError(err, dialCtx)
		return res
	}

	res.Latency = time.Since(start)
	res.State = model.StateOpen
	conn.Close()
	return res
}

// classifyError figures out what kind of failure a dial error represents.
// Order matters here: check the context deadline before poking at syscall
// errnos, since a timed-out dial can surface either way depending on OS.
func classifyError(err error, dialCtx context.Context) (model.State, model.ErrorType) {
	if errors.Is(err, context.DeadlineExceeded) || dialCtx.Err() == context.DeadlineExceeded {
		return model.StateTimeout, model.ErrTimeout
	}
	if errors.Is(err, errConnRefused) {
		return model.StateClosed, model.ErrConnectionRefused
	}
	if errors.Is(err, errNetUnreachable) {
		return model.StateError, model.ErrNetworkUnreachable
	}
	if errors.Is(err, errHostUnreachable) {
		return model.StateError, model.ErrHostUnreachable
	}
	return model.StateError, model.ErrUnknown
}
