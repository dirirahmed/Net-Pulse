// Package netwatch monitors network targets on a schedule. It is the bridge
// between the agent and the diagnostics engine: every configured target is
// checked with engine.Run (DNS, TCP, TLS, HTTP) through the safety guard,
// classified as up / degraded / down, kept in memory for the dashboard,
// written to the history database, and fed to its own alert engine so an
// outage, a slow service or an expiring certificate raises an alert like any
// other.
package netwatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/analyzer"
	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/result"
	"github.com/dirirahmed/Net-Pulse/internal/safety"
)

const (
	// maxConcurrentChecks bounds outbound work no matter how many targets
	// come due at once.
	maxConcurrentChecks = 4
	// recentChecks is how many results per target are kept in memory for
	// sparklines and the "last checks" list.
	recentChecks = 60
	// startStagger spreads the first checks after start-up so a list of
	// targets doesn't fire as one burst.
	startStagger = 2 * time.Second
	// checkBudget caps one check end to end, whatever the interval.
	checkBudget        = 25 * time.Second
	storageCallTimeout = 5 * time.Second
	schedulerTick      = time.Second
)

var (
	// ErrUnknownTarget is returned for an id that isn't configured.
	ErrUnknownTarget = errors.New("unknown target")
	// ErrNoHistory means the history database isn't available.
	ErrNoHistory = errors.New("history storage is unavailable")
)

// Store is the subset of storage.Store netwatch uses. Nil disables history.
type Store interface {
	SaveNetCheck(ctx context.Context, c models.NetCheck) error
	QueryNetChecks(ctx context.Context, target string, from, to time.Time, bucket time.Duration) ([]models.NetCheckPoint, error)
	NetUptime(ctx context.Context, target string, since time.Time) (models.NetUptime, error)
	SaveAlert(ctx context.Context, a models.Alert) error
}

// Runner runs one diagnostics pass; engine.Run in production.
type Runner func(ctx context.Context, t result.Target, opts engine.Options) result.Report

type Options struct {
	Config *config.Store
	Store  Store // may be nil
	Logger *slog.Logger
	Runner Runner           // nil means engine.Run
	Now    func() time.Time // nil means time.Now; tests pin it
}

// TargetStatus is the live view of one monitored target.
type TargetStatus struct {
	ID     string           `json:"id"`
	Name   string           `json:"name"`
	Target string           `json:"target"`
	Status models.NetStatus `json:"status"`
	// Last is the most recent completed check, nil before the first one.
	Last *models.NetCheck `json:"last"`
	// Since is when Status last changed.
	Since               *time.Time `json:"since"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	Checking            bool       `json:"checking"`
	NextCheckAt         time.Time  `json:"nextCheckAt"`
	// Recent holds the latest checks, oldest first.
	Recent []models.NetCheck `json:"recent"`
}

type targetState struct {
	cfg        config.NetTarget
	status     models.NetStatus
	last       *models.NetCheck
	since      time.Time
	failures   int // consecutive down checks
	slowStreak int // consecutive checks at or over the slow limit
	certDays   *int
	checking   bool
	nextAt     time.Time
	recent     []models.NetCheck
}

type Service struct {
	cfg   *config.Store
	store Store
	log   *slog.Logger
	run   Runner
	now   func() time.Time
	wake  chan struct{}
	sem   chan struct{}
	wg    sync.WaitGroup

	mu         sync.Mutex
	order      []string // configured order, for stable listing
	targets    map[string]*targetState
	alerts     *analyzer.AlertEngine
	active     []models.Alert
	storageErr string
}

func New(o Options) *Service {
	s := &Service{
		cfg: o.Config, store: o.Store, log: o.Logger, run: o.Runner, now: o.Now,
		wake: make(chan struct{}, 1), sem: make(chan struct{}, maxConcurrentChecks),
		targets: map[string]*targetState{}, alerts: analyzer.NewAlertEngine(), active: []models.Alert{},
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.run == nil {
		s.run = engine.Run
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Run schedules checks until ctx is cancelled, then waits for in-flight
// checks to finish.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(schedulerTick)
	defer ticker.Stop()
	defer s.wg.Wait()
	for {
		s.sync()
		s.dispatch(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}

// Reconfigure makes the scheduler pick up changed targets immediately rather
// than on its next tick.
func (s *Service) Reconfigure() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// CheckNow moves a target's next check to now.
func (s *Service) CheckNow(id string) error {
	s.sync()
	s.mu.Lock()
	st, ok := s.targets[id]
	if ok && !st.checking {
		st.nextAt = s.now()
	}
	s.mu.Unlock()
	if !ok {
		return ErrUnknownTarget
	}
	s.Reconfigure()
	return nil
}

// sync reconciles in-memory state with the configured targets.
func (s *Service) sync() {
	n := s.cfg.Get().Network
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	order := make([]string, 0, len(n.Targets))
	keep := make(map[string]bool, len(n.Targets))
	added := 0
	for _, t := range n.Targets {
		order = append(order, t.ID)
		keep[t.ID] = true
		st, ok := s.targets[t.ID]
		if ok && st.cfg.Target == t.Target {
			st.cfg.Name = t.Name
			if st.last != nil && !st.checking {
				// A shorter interval applies right away.
				if next := st.last.Timestamp.Add(interval(n)); next.Before(st.nextAt) {
					st.nextAt = next
				}
			}
			continue
		}
		// New target, or the same id now pointing somewhere else: start over.
		s.targets[t.ID] = &targetState{cfg: t, status: models.NetPending, nextAt: now.Add(time.Duration(added) * startStagger)}
		added++
	}
	removed := false
	for id := range s.targets {
		if !keep[id] {
			delete(s.targets, id)
			removed = true
		}
	}
	s.order = order
	if removed {
		// Alerts for removed targets resolve as "no longer reported".
		s.evaluateLocked(now, n)
	}
}

// dispatch starts every check that is due, up to the concurrency limit.
func (s *Service) dispatch(ctx context.Context) {
	now := s.now()
	s.mu.Lock()
	var due []config.NetTarget
	for _, id := range s.order {
		st := s.targets[id]
		if st == nil || st.checking || now.Before(st.nextAt) {
			continue
		}
		st.checking = true
		due = append(due, st.cfg)
	}
	s.mu.Unlock()

	for _, t := range due {
		s.wg.Add(1)
		go func(t config.NetTarget) {
			defer s.wg.Done()
			select {
			case s.sem <- struct{}{}:
			case <-ctx.Done():
				s.release(t.ID)
				return
			}
			defer func() { <-s.sem }()
			s.checkTarget(ctx, t)
		}(t)
	}
}

func (s *Service) release(id string) {
	s.mu.Lock()
	if st := s.targets[id]; st != nil {
		st.checking = false
	}
	s.mu.Unlock()
}

func (s *Service) checkTarget(ctx context.Context, t config.NetTarget) {
	cfg := s.cfg.Get()
	n := cfg.Network
	c := s.probe(ctx, t, n)
	if ctx.Err() != nil {
		// Shutting down: a cancelled check says nothing about the target.
		s.release(t.ID)
		return
	}
	now := s.now()
	if c.Timestamp.IsZero() {
		c.Timestamp = now.UTC()
	}

	s.mu.Lock()
	st := s.targets[t.ID]
	if st == nil || st.cfg.Target != t.Target {
		// Removed or re-pointed while the check ran.
		s.mu.Unlock()
		return
	}
	prev := st.status
	st.checking = false
	st.nextAt = now.Add(interval(n))
	s.apply(st, c, n)
	events := s.evaluateLocked(now, n)
	s.mu.Unlock()

	if prev != c.Status {
		s.log.Info("network target "+string(c.Status), "target", t.Name, "was", string(prev), "problem", c.Problem)
	}
	s.persist(ctx, func(ctx context.Context) error { return s.store.SaveNetCheck(ctx, c) })
	for _, ev := range events {
		s.log.Info("alert "+string(ev.Type), "rule", ev.Alert.Rule, "severity", ev.Alert.Severity, "reason", ev.Alert.Reason)
		s.persist(ctx, func(ctx context.Context) error { return s.store.SaveAlert(ctx, ev.Alert) })
	}
}

// probe runs one check. The guard is applied on every check rather than only
// when the target is saved: what a hostname resolves to can change.
func (s *Service) probe(ctx context.Context, t config.NetTarget, n config.Network) models.NetCheck {
	ctx, cancel := context.WithTimeout(ctx, checkBudget)
	defer cancel()
	start := s.now().UTC()

	target, err := engine.ParseTarget(t.Target)
	if err != nil {
		return models.NetCheck{TargetID: t.ID, Timestamp: start, Status: models.NetDown, Problem: "invalid target: " + err.Error()}
	}
	guard := &safety.Guard{AllowPrivate: n.AllowPrivateTargets}
	if err := guard.CheckTarget(ctx, target.Host); err != nil {
		var blocked *safety.BlockedError
		if errors.As(err, &blocked) {
			return models.NetCheck{TargetID: t.ID, Timestamp: start, Status: models.NetBlocked,
				Problem: blocked.Error() + ". Turn on \"Allow private targets\" in Settings to monitor it."}
		}
		return models.NetCheck{TargetID: t.ID, Timestamp: start, Status: models.NetDown, Problem: "DNS lookup failed: " + err.Error()}
	}

	rep := s.run(ctx, target, engine.Options{
		Checks:          engine.Checks{DNS: true, TCP: true, TLS: true, HTTP: true},
		DNSTimeout:      3 * time.Second,
		DialTimeout:     5 * time.Second,
		TLSTimeout:      5 * time.Second,
		HTTPTimeout:     10 * time.Second,
		TotalTimeout:    checkBudget,
		HTTPMethod:      "GET",
		FollowRedirects: true,
		MaxRedirects:    5,
		Dialer:          guard.Dialer(),
		// Through a proxy the guard's dialer would only see the proxy.
		DisableProxy: !n.AllowPrivateTargets,
	})
	c := Classify(rep, t.ID, n.SlowResponseMs)
	if c.Timestamp.IsZero() {
		c.Timestamp = start
	}
	return c
}

// apply folds a finished check into the target's state.
func (s *Service) apply(st *targetState, c models.NetCheck, n config.Network) {
	if c.Status != st.status {
		st.status = c.Status
		st.since = c.Timestamp
	}
	cc := c
	st.last = &cc
	switch c.Status {
	case models.NetDown:
		st.failures++
		st.slowStreak = 0
	case models.NetBlocked:
		st.failures, st.slowStreak = 0, 0
	default:
		st.failures = 0
		if c.ResponseMs != nil && *c.ResponseMs >= float64(n.SlowResponseMs) {
			st.slowStreak++
		} else {
			st.slowStreak = 0
		}
	}
	// Keep the last known certificate expiry through a failed check, so a
	// short outage doesn't resolve (and later re-open) an expiry alert.
	if c.CertDaysLeft != nil {
		d := *c.CertDaysLeft
		st.certDays = &d
	}
	st.recent = append(st.recent, c)
	if over := len(st.recent) - recentChecks; over > 0 {
		st.recent = append([]models.NetCheck(nil), st.recent[over:]...)
	}
}

// evaluateLocked runs the alert engine over every target. It must see all
// targets on every call: the engine resolves any key it doesn't see.
func (s *Service) evaluateLocked(now time.Time, n config.Network) []analyzer.Event {
	var obs []analyzer.Observation
	for _, id := range s.order {
		if st := s.targets[id]; st != nil {
			obs = append(obs, observations(st, n)...)
		}
	}
	events := s.alerts.Evaluate(now, obs, time.Duration(s.cfg.Get().AlertCooldownSeconds)*time.Second)
	s.active = s.alerts.Active()
	return events
}

// observations maps one target onto three rules: unreachable, slow, and
// certificate expiry. Counts of consecutive checks are used instead of
// sustain times because a target produces one value per check interval.
func observations(st *targetState, n config.Network) []analyzer.Observation {
	if st.last == nil || st.status == models.NetBlocked {
		return nil
	}
	name, id := st.cfg.Name, st.cfg.ID
	need := float64(n.FailuresBeforeAlert)
	failures, slow, problem := st.failures, st.slowStreak, st.last.Problem
	var lastMs float64
	if st.last.ResponseMs != nil {
		lastMs = *st.last.ResponseMs
	}
	obs := []analyzer.Observation{
		{
			Key: "net_down:" + id, Rule: "net_down", Component: "network", Target: name,
			Title: name + " is unreachable", Value: float64(failures),
			Levels: []analyzer.Level{{Severity: models.SeverityCritical, Threshold: need}},
			// Resolves on the first successful check.
			Hysteresis: need - 0.5,
			Describe: func(analyzer.Level) string {
				return fmt.Sprintf("%s failed %s in a row. %s", name, plural(failures, "check"), problem)
			},
		},
		{
			Key: "net_slow:" + id, Rule: "net_slow", Component: "network", Target: name,
			Title: name + " is responding slowly", Value: float64(slow),
			Levels:     []analyzer.Level{{Severity: models.SeverityWarning, Threshold: need}},
			Hysteresis: need - 0.5,
			Describe: func(analyzer.Level) string {
				return fmt.Sprintf("%s took at least %d ms on %s in a row (last %.0f ms).", name, n.SlowResponseMs, plural(slow, "check"), lastMs)
			},
		},
	}
	if st.certDays != nil {
		days := *st.certDays
		obs = append(obs, analyzer.Observation{
			Key: "net_cert:" + id, Rule: "net_cert_expiry", Component: "network", Target: name,
			Title: name + " TLS certificate", Value: float64(days), Below: true,
			Levels: []analyzer.Level{
				{Severity: models.SeverityWarning, Threshold: float64(n.CertExpiry.WarningDays)},
				{Severity: models.SeverityCritical, Threshold: float64(n.CertExpiry.CriticalDays)},
			},
			Hysteresis: 0.5,
			Describe: func(lvl analyzer.Level) string {
				if days < 0 {
					return fmt.Sprintf("The TLS certificate for %s expired %d days ago.", name, -days)
				}
				return fmt.Sprintf("The TLS certificate for %s expires in %d days (%s at %.0f days or less).", name, days, lvl.Severity, lvl.Threshold)
			},
		})
	}
	return obs
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func interval(n config.Network) time.Duration {
	return time.Duration(n.CheckIntervalSeconds) * time.Second
}

// persist mirrors the monitor: storage failures degrade history but never
// stop monitoring, and are logged once per change.
func (s *Service) persist(parent context.Context, fn func(context.Context) error) {
	if s.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), storageCallTimeout)
	defer cancel()
	err := fn(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case err != nil && s.storageErr != err.Error():
		s.log.Error("network history write failed", "err", err)
		s.storageErr = err.Error()
	case err == nil && s.storageErr != "":
		s.log.Info("network history writes recovered")
		s.storageErr = ""
	}
}

// ---- read side ----

// Targets returns every configured target in configured order.
func (s *Service) Targets() []TargetStatus {
	s.sync()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TargetStatus, 0, len(s.order))
	for _, id := range s.order {
		if st := s.targets[id]; st != nil {
			out = append(out, view(st))
		}
	}
	return out
}

// Target returns one target's live status.
func (s *Service) Target(id string) (TargetStatus, bool) {
	s.sync()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.targets[id]
	if st == nil {
		return TargetStatus{}, false
	}
	return view(st), true
}

func view(st *targetState) TargetStatus {
	v := TargetStatus{
		ID: st.cfg.ID, Name: st.cfg.Name, Target: st.cfg.Target, Status: st.status,
		ConsecutiveFailures: st.failures, Checking: st.checking, NextCheckAt: st.nextAt,
		Recent: append([]models.NetCheck{}, st.recent...),
	}
	if st.last != nil {
		last := *st.last
		v.Last = &last
	}
	if !st.since.IsZero() {
		since := st.since
		v.Since = &since
	}
	return v
}

// ActiveAlerts returns open network alerts, most severe first.
func (s *Service) ActiveAlerts() []models.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.Alert{}, s.active...)
}

// History returns one target's checks over the trailing period, bucketed to
// about maxPoints points and never finer than the check interval.
func (s *Service) History(ctx context.Context, id string, period time.Duration, maxPoints int) ([]models.NetCheckPoint, time.Duration, error) {
	if _, ok := s.cfg.Get().Network.TargetByID(id); !ok {
		return nil, 0, ErrUnknownTarget
	}
	if s.store == nil {
		return nil, 0, ErrNoHistory
	}
	bucket := max(interval(s.cfg.Get().Network), (period / time.Duration(max(maxPoints, 1))).Round(time.Second))
	now := s.now()
	pts, err := s.store.QueryNetChecks(ctx, id, now.Add(-period), now, bucket)
	return pts, bucket, err
}

// Uptime counts one target's checks over the trailing period.
func (s *Service) Uptime(ctx context.Context, id string, period time.Duration) (models.NetUptime, error) {
	if s.store == nil {
		return models.NetUptime{}, ErrNoHistory
	}
	return s.store.NetUptime(ctx, id, s.now().Add(-period))
}
