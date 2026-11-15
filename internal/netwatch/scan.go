package netwatch

import (
	"context"
	"errors"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/result"
	"github.com/dirirahmed/Net-Pulse/internal/safety"
)

const (
	// MaxScanPorts caps a port scan started from the dashboard. The CLI has
	// no cap because whoever runs it owns the machine and the target.
	MaxScanPorts = 1024
	// scanConcurrency is lower than the CLI's default: the agent is a
	// background process and shouldn't burst hundreds of connections.
	scanConcurrency = 50
	scanBudget      = 60 * time.Second
)

// ErrScanBusy means another on-demand scan is still running.
var ErrScanBusy = errors.New("a scan is already running; try again when it finishes")

// ScanRequest is an on-demand diagnostics run. The caller parses and
// validates the target, checks and ports.
type ScanRequest struct {
	Target result.Target
	Checks engine.Checks
	Ports  []int
}

// Scan runs one diagnostics pass through the target guard. It returns a
// *safety.BlockedError when the target is refused by policy, ErrScanBusy
// when another scan is running, and otherwise always a report: failures
// such as an unresolvable name belong in the report, as in the CLI.
func (s *Service) Scan(ctx context.Context, req ScanRequest) (result.Report, error) {
	if !s.scanMu.TryLock() {
		return result.Report{}, ErrScanBusy
	}
	defer s.scanMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, scanBudget)
	defer cancel()
	n := s.cfg.Get().Network
	guard := &safety.Guard{AllowPrivate: n.AllowPrivateTargets}
	if err := guard.CheckTarget(ctx, req.Target.Host); err != nil {
		var blocked *safety.BlockedError
		if errors.As(err, &blocked) {
			return result.Report{}, blocked
		}
		// Not resolvable right now: let the DNS check report that. The
		// guarded dialer still refuses whatever the name resolves to later.
	}

	opts := engine.DefaultOptions()
	opts.Checks = req.Checks
	if len(req.Ports) > 0 {
		opts.Ports = req.Ports
	}
	opts.Concurrency = scanConcurrency
	opts.TotalTimeout = scanBudget
	opts.Dialer = guard.Dialer()
	opts.DisableProxy = !n.AllowPrivateTargets
	return s.run(ctx, req.Target, opts), nil
}

// CheckAllowed reports whether a target would pass the guard right now. It
// returns a *safety.BlockedError for a refused target and nil otherwise; a
// name that doesn't resolve yet is allowed, since it may be temporary.
func (s *Service) CheckAllowed(ctx context.Context, raw string) error {
	t, err := engine.ParseTarget(raw)
	if err != nil {
		return err
	}
	guard := &safety.Guard{AllowPrivate: s.cfg.Get().Network.AllowPrivateTargets}
	var blocked *safety.BlockedError
	if err := guard.CheckTarget(ctx, t.Host); errors.As(err, &blocked) {
		return blocked
	}
	return nil
}
