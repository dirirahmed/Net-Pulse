package netwatch

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeStore struct {
	mu     sync.Mutex
	checks []models.NetCheck
	alerts []models.Alert
}

func (f *fakeStore) SaveNetCheck(_ context.Context, c models.NetCheck) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, c)
	return nil
}
func (f *fakeStore) QueryNetChecks(context.Context, string, time.Time, time.Time, time.Duration) ([]models.NetCheckPoint, error) {
	return []models.NetCheckPoint{{Checks: 1, Up: 1}}, nil
}
func (f *fakeStore) NetUptime(context.Context, string, time.Time) (models.NetUptime, error) {
	return models.NetUptime{Checks: 4, Up: 3, Down: 1}, nil
}
func (f *fakeStore) SaveAlert(_ context.Context, a models.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a)
	return nil
}

// harness drives the scheduler by hand with a fake clock and a runner whose
// next report can be swapped between steps.
type harness struct {
	t      *testing.T
	svc    *Service
	cfg    *config.Store
	store  *fakeStore
	now    time.Time
	mu     sync.Mutex
	report func(result.Target) result.Report
	runs   atomic.Int64
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	c := config.Default()
	// The fake runner never touches the network, so the guard can be off;
	// guarded behaviour has its own tests below.
	c.Network.AllowPrivateTargets = true
	c.Network.Targets = []config.NetTarget{{ID: "site", Name: "My site", Target: "https://example.com"}}
	if mutate != nil {
		mutate(&c)
	}
	h := &harness{t: t, cfg: config.NewStore("", c), store: &fakeStore{}, now: t0}
	h.report = func(result.Target) result.Report { return healthy() }
	h.svc = New(Options{
		Config: h.cfg, Store: h.store, Logger: quiet,
		Now: func() time.Time {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.now
		},
		Runner: func(_ context.Context, tg result.Target, _ engine.Options) result.Report {
			h.runs.Add(1)
			h.mu.Lock()
			fn, now := h.report, h.now
			h.mu.Unlock()
			r := fn(tg)
			r.StartedAt = now
			return r
		},
	})
	return h
}

// step advances the clock and runs one scheduler pass to completion.
func (h *harness) step(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
	h.svc.sync()
	h.svc.dispatch(context.Background())
	h.svc.wg.Wait()
}

func (h *harness) set(fn func(result.Target) result.Report) {
	h.mu.Lock()
	h.report = fn
	h.mu.Unlock()
}

func refused(result.Target) result.Report {
	r := healthy()
	r.TCP = &result.TCPResult{Address: "x:443", Status: result.StatusClosed, Error: &result.ProbeError{Kind: result.ErrKindRefused, Message: "connection refused"}}
	r.TLS, r.HTTP = nil, nil
	return r
}

func (h *harness) target() TargetStatus {
	ts, ok := h.svc.Target("site")
	if !ok {
		h.t.Fatal("target missing")
	}
	return ts
}

func TestFirstCheckRunsImmediatelyThenOnInterval(t *testing.T) {
	h := newHarness(t, nil)
	if got := h.target().Status; got != models.NetPending {
		t.Fatalf("before any check: %s", got)
	}
	h.step(0)
	ts := h.target()
	if ts.Status != models.NetUp || ts.Last == nil || len(ts.Recent) != 1 || h.runs.Load() != 1 {
		t.Fatalf("after first check: %+v runs=%d", ts, h.runs.Load())
	}
	h.step(30 * time.Second)
	if h.runs.Load() != 1 {
		t.Fatal("checked again before the 60 s interval")
	}
	h.step(30 * time.Second)
	if h.runs.Load() != 2 {
		t.Fatalf("runs = %d after one interval, want 2", h.runs.Load())
	}
	if len(h.store.checks) != 2 {
		t.Errorf("persisted %d checks, want 2", len(h.store.checks))
	}
}

func TestCheckNow(t *testing.T) {
	h := newHarness(t, nil)
	h.step(0)
	if err := h.svc.CheckNow("site"); err != nil {
		t.Fatal(err)
	}
	h.step(time.Second)
	if h.runs.Load() != 2 {
		t.Fatalf("runs = %d, want an immediate second check", h.runs.Load())
	}
	if err := h.svc.CheckNow("nope"); err != ErrUnknownTarget {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestDownAlertOpensAfterConsecutiveFailuresAndResolves(t *testing.T) {
	h := newHarness(t, nil) // failuresBeforeAlert defaults to 3
	h.step(0)
	h.set(refused)
	for i := 1; i <= 2; i++ {
		h.step(time.Minute)
		if n := len(h.svc.ActiveAlerts()); n != 0 {
			t.Fatalf("alert opened after %d failure(s)", i)
		}
	}
	if ts := h.target(); ts.Status != models.NetDown || ts.ConsecutiveFailures != 2 {
		t.Fatalf("status %s failures %d", ts.Status, ts.ConsecutiveFailures)
	}
	h.step(time.Minute)
	active := h.svc.ActiveAlerts()
	if len(active) != 1 || active[0].Rule != "net_down" || active[0].Severity != models.SeverityCritical {
		t.Fatalf("active = %+v", active)
	}
	if !strings.Contains(active[0].Reason, "failed 3 checks in a row") || !strings.Contains(active[0].Reason, "connection refused") {
		t.Errorf("reason = %q", active[0].Reason)
	}
	if active[0].Component != "network" || active[0].Target != "My site" {
		t.Errorf("component/target = %s/%s", active[0].Component, active[0].Target)
	}

	h.set(func(result.Target) result.Report { return healthy() })
	h.step(time.Minute)
	if n := len(h.svc.ActiveAlerts()); n != 0 {
		t.Fatalf("alert still open after recovery: %+v", h.svc.ActiveAlerts())
	}
	// opened + resolved were both persisted.
	if len(h.store.alerts) != 2 || h.store.alerts[1].ResolvedAt == nil {
		t.Errorf("persisted alerts = %+v", h.store.alerts)
	}
	if ts := h.target(); ts.Since == nil || !ts.Since.Equal(h.now) {
		t.Errorf("since = %v, want the recovery time", ts.Since)
	}
}

func TestSlowAlert(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Network.FailuresBeforeAlert = 2 })
	h.set(func(result.Target) result.Report {
		r := healthy()
		r.HTTP.Duration = ms(2500)
		return r
	})
	h.step(0)
	h.step(time.Minute)
	active := h.svc.ActiveAlerts()
	if len(active) != 1 || active[0].Rule != "net_slow" || active[0].Severity != models.SeverityWarning {
		t.Fatalf("active = %+v", active)
	}
	if h.target().Status != models.NetDegraded {
		t.Errorf("slow target should be degraded, got %s", h.target().Status)
	}
}

func TestCertificateAlertEscalatesAndSurvivesAnOutage(t *testing.T) {
	h := newHarness(t, nil)
	days := 20 // under the 21-day warning
	h.set(func(result.Target) result.Report {
		r := healthy()
		r.TLS.Certificates[0].DaysUntilExpiry = days
		return r
	})
	h.step(0)
	active := h.svc.ActiveAlerts()
	if len(active) != 1 || active[0].Rule != "net_cert_expiry" || active[0].Severity != models.SeverityWarning {
		t.Fatalf("active = %+v", active)
	}
	if !strings.Contains(active[0].Reason, "expires in 20 days") {
		t.Errorf("reason = %q", active[0].Reason)
	}
	id := active[0].ID

	// A failed check carries no certificate; the alert must not flap.
	h.set(refused)
	h.step(time.Minute)
	if a := h.svc.ActiveAlerts(); len(a) != 1 || a[0].ID != id {
		t.Fatalf("certificate alert lost during an outage: %+v", a)
	}

	days = 5
	h.set(func(result.Target) result.Report {
		r := healthy()
		r.TLS.Certificates[0].DaysUntilExpiry = days
		return r
	})
	h.step(time.Minute)
	a := h.svc.ActiveAlerts()
	if len(a) != 1 || a[0].ID != id || a[0].Severity != models.SeverityCritical {
		t.Fatalf("want the same alert escalated to critical, got %+v", a)
	}
}

func TestRemovingATargetResolvesItsAlerts(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Network.FailuresBeforeAlert = 1 })
	h.set(refused)
	h.step(0)
	if len(h.svc.ActiveAlerts()) != 1 {
		t.Fatal("expected a down alert")
	}
	c := h.cfg.Get()
	c.Network.Targets = []config.NetTarget{}
	if err := h.cfg.Update(c); err != nil {
		t.Fatal(err)
	}
	h.step(time.Second)
	if len(h.svc.ActiveAlerts()) != 0 || len(h.svc.Targets()) != 0 {
		t.Fatalf("alerts=%+v targets=%+v", h.svc.ActiveAlerts(), h.svc.Targets())
	}
}

func TestRepointingATargetStartsOver(t *testing.T) {
	h := newHarness(t, nil)
	h.step(0)
	c := h.cfg.Get()
	c.Network.Targets[0].Target = "https://example.org"
	c.Network.Targets[0].Name = "Renamed"
	h.cfg.Update(c)
	ts := h.target()
	if ts.Status != models.NetPending || ts.Last != nil || ts.Name != "Renamed" {
		t.Fatalf("after re-pointing: %+v", ts)
	}
}

func TestRenameKeepsHistory(t *testing.T) {
	h := newHarness(t, nil)
	h.step(0)
	c := h.cfg.Get()
	c.Network.Targets[0].Name = "Renamed"
	h.cfg.Update(c)
	if ts := h.target(); ts.Name != "Renamed" || ts.Last == nil {
		t.Fatalf("rename lost state: %+v", ts)
	}
}

func TestRecentIsBounded(t *testing.T) {
	h := newHarness(t, nil)
	for i := 0; i < recentChecks+5; i++ {
		h.step(time.Minute)
	}
	if n := len(h.target().Recent); n != recentChecks {
		t.Fatalf("recent = %d, want %d", n, recentChecks)
	}
}

func TestHistoryAndUptimeDelegateToStore(t *testing.T) {
	h := newHarness(t, nil)
	pts, bucket, err := h.svc.History(context.Background(), "site", 24*time.Hour, 300)
	if err != nil || len(pts) != 1 {
		t.Fatalf("history: %v %v", pts, err)
	}
	if bucket != 4*time.Minute+48*time.Second {
		t.Errorf("bucket = %s, want 24h/300 = 4m48s", bucket)
	}
	// Buckets are never finer than the 60 s check interval.
	if _, b, _ := h.svc.History(context.Background(), "site", time.Hour, 300); b != time.Minute {
		t.Errorf("1h bucket = %s, want the 1m check interval", b)
	}
	if _, _, err := h.svc.History(context.Background(), "nope", time.Hour, 300); err != ErrUnknownTarget {
		t.Errorf("unknown target: %v", err)
	}
	u, err := h.svc.Uptime(context.Background(), "site", 24*time.Hour)
	if err != nil || u.Checks != 4 {
		t.Errorf("uptime: %+v %v", u, err)
	}
}

func TestNoStoreMeansNoHistory(t *testing.T) {
	cfg := config.NewStore("", config.Default())
	svc := New(Options{Config: cfg, Logger: quiet})
	c := cfg.Get()
	c.Network.Targets = []config.NetTarget{{ID: "a", Name: "A", Target: "a.example"}}
	cfg.Update(c)
	if _, _, err := svc.History(context.Background(), "a", time.Hour, 100); err != ErrNoHistory {
		t.Fatalf("err = %v", err)
	}
}

// ---- real engine, real sockets (loopback only, no internet needed) ----

func realService(t *testing.T, target string, allowPrivate bool) *Service {
	t.Helper()
	c := config.Default()
	c.Network.AllowPrivateTargets = allowPrivate
	c.Network.Targets = []config.NetTarget{{ID: "local", Name: "Local", Target: target}}
	return New(Options{Config: config.NewStore(filepath.Join(t.TempDir(), "c.json"), c), Logger: quiet})
}

func runOnce(svc *Service) {
	svc.sync()
	svc.dispatch(context.Background())
	svc.wg.Wait()
}

func TestRealCheckAgainstLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	svc := realService(t, srv.URL+"/health", true)
	runOnce(svc)
	ts, _ := svc.Target("local")
	if ts.Status != models.NetUp || ts.Last == nil || ts.Last.HTTPStatus == nil || *ts.Last.HTTPStatus != http.StatusNoContent {
		t.Fatalf("status = %s last = %+v", ts.Status, ts.Last)
	}
	if ts.Last.ConnectMs == nil || ts.Last.ResponseMs == nil {
		t.Errorf("timings missing: %+v", ts.Last)
	}
}

func TestGuardBlocksPrivateTargetsByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the guard let a request through to a loopback server")
	}))
	defer srv.Close()

	svc := realService(t, srv.URL, false)
	runOnce(svc)
	ts, _ := svc.Target("local")
	if ts.Status != models.NetBlocked || !strings.Contains(ts.Last.Problem, "Allow private targets") {
		t.Fatalf("status = %s problem = %q", ts.Status, ts.Last.Problem)
	}
	if len(svc.ActiveAlerts()) != 0 {
		t.Error("a blocked target is a setting, not an outage: no alert expected")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	svc := realService(t, "127.0.0.1:1", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Run(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
