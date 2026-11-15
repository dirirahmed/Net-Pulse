package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/netwatch"
	"github.com/dirirahmed/Net-Pulse/internal/probe"
	"github.com/dirirahmed/Net-Pulse/internal/result"
	"github.com/dirirahmed/Net-Pulse/internal/safety"
)

// fakeNetwork reads targets from the config store, like netwatch does.
type fakeNetwork struct {
	cfg        *config.Store
	historyErr error
	uptimeErr  error
	scanErr    error
	blockAdd   bool
	lastScan   *netwatch.ScanRequest
	checked    string
	reconfigs  int
}

func (f *fakeNetwork) Targets() []netwatch.TargetStatus {
	out := []netwatch.TargetStatus{}
	for _, t := range f.cfg.Get().Network.Targets {
		out = append(out, netwatch.TargetStatus{ID: t.ID, Name: t.Name, Target: t.Target, Status: models.NetUp})
	}
	return out
}
func (f *fakeNetwork) Target(id string) (netwatch.TargetStatus, bool) {
	for _, t := range f.Targets() {
		if t.ID == id {
			return t, true
		}
	}
	return netwatch.TargetStatus{}, false
}
func (f *fakeNetwork) CheckNow(id string) error {
	if _, ok := f.Target(id); !ok {
		return netwatch.ErrUnknownTarget
	}
	f.checked = id
	return nil
}
func (f *fakeNetwork) ActiveAlerts() []models.Alert {
	return []models.Alert{{ID: "n", Rule: "net_down", Component: "network", Severity: models.SeverityCritical}}
}
func (f *fakeNetwork) History(_ context.Context, id string, _ time.Duration, _ int) ([]models.NetCheckPoint, time.Duration, error) {
	if _, ok := f.Target(id); !ok {
		return nil, 0, netwatch.ErrUnknownTarget
	}
	return []models.NetCheckPoint{{Checks: 2, Up: 2}}, time.Minute, f.historyErr
}
func (f *fakeNetwork) Uptime(context.Context, string, time.Duration) (models.NetUptime, error) {
	return models.NetUptime{Checks: 4, Up: 3, Down: 1}, f.uptimeErr
}
func (f *fakeNetwork) Scan(_ context.Context, req netwatch.ScanRequest) (result.Report, error) {
	f.lastScan = &req
	if f.scanErr != nil {
		return result.Report{}, f.scanErr
	}
	return result.Report{Target: req.Target, Notes: []string{"fake"}}, nil
}
func (f *fakeNetwork) CheckAllowed(context.Context, string) error {
	if f.blockAdd {
		return &safety.BlockedError{Target: "192.168.1.1", Reason: "it is a private network (RFC 1918)"}
	}
	return nil
}
func (f *fakeNetwork) Reconfigure() { f.reconfigs++ }

func newNetworkServer(t *testing.T, targets ...config.NetTarget) (http.Handler, *fakeNetwork, *config.Store) {
	t.Helper()
	c := config.Default()
	c.Network.Targets = append([]config.NetTarget{}, targets...)
	cfg := config.NewStore(filepath.Join(t.TempDir(), "config.json"), c)
	n := &fakeNetwork{cfg: cfg}
	return New(&fakeSource{snap: sampleSnapshot()}, cfg, nil, nil).WithNetwork(n).Handler(), n, cfg
}

var site = config.NetTarget{ID: "site", Name: "My site", Target: "https://example.com"}

func TestTargetsListIncludesUptime(t *testing.T) {
	h, _, _ := newNetworkServer(t, site)
	rec := do(t, h, "GET", "/api/targets", "", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := decode[TargetsResponse](t, rec)
	if len(got.Targets) != 1 || got.Targets[0].ID != "site" || got.Targets[0].Status != models.NetUp {
		t.Fatalf("targets = %+v", got.Targets)
	}
	if u := got.Targets[0].Uptime24h; u == nil || *u != 75 || got.Targets[0].Checks24h != 4 {
		t.Errorf("uptime = %v checks = %d", u, got.Targets[0].Checks24h)
	}
	if !got.HistoryAvailable || got.AllowPrivateTargets || got.CheckIntervalSeconds != 60 || got.MaxTargets != config.MaxTargets {
		t.Errorf("response = %+v", got)
	}
	// TargetStatus fields are flattened into each target, not nested.
	if !strings.Contains(rec.Body.String(), `"name":"My site"`) {
		t.Errorf("body: %s", rec.Body)
	}
}

func TestTargetsListWithoutHistory(t *testing.T) {
	h, n, _ := newNetworkServer(t, site)
	n.uptimeErr = netwatch.ErrNoHistory
	got := decode[TargetsResponse](t, do(t, h, "GET", "/api/targets", "", nil))
	if got.HistoryAvailable || got.HistoryError == "" || got.Targets[0].Uptime24h != nil {
		t.Errorf("want live targets with history marked unavailable, got %+v", got)
	}
}

func TestAddTarget(t *testing.T) {
	h, n, cfg := newNetworkServer(t, site)
	rec := do(t, h, "POST", "/api/targets", `{"name": "My Site!", "target": "https://example.org/health"}`, jsonHeader)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := decode[TargetView](t, rec)
	// "My Site!" slugifies to "my-site", which is free; the existing id is "site".
	if got.ID != "my-site" || got.Name != "My Site!" {
		t.Errorf("created = %+v", got)
	}
	targets := cfg.Get().Network.Targets
	if len(targets) != 2 || targets[1].Target != "https://example.org/health" || n.reconfigs != 1 {
		t.Errorf("saved = %+v reconfigs = %d", targets, n.reconfigs)
	}

	// A name that slugifies to a taken id gets a suffix.
	got = decode[TargetView](t, do(t, h, "POST", "/api/targets", `{"name": "site", "target": "1.1.1.1:53"}`, jsonHeader))
	if got.ID != "site-2" {
		t.Errorf("duplicate id = %q, want site-2", got.ID)
	}
	// The name defaults to the target.
	got = decode[TargetView](t, do(t, h, "POST", "/api/targets", `{"target": "8.8.8.8:53"}`, jsonHeader))
	if got.Name != "8.8.8.8:53" || got.ID != "8-8-8-8-53" {
		t.Errorf("unnamed target = %+v", got)
	}
}

func TestAddTargetRejections(t *testing.T) {
	h, n, cfg := newNetworkServer(t)
	for body, want := range map[string]int{
		`{"target": "ftp://example.com"}`: http.StatusBadRequest,
		`{"target": ""}`:                  http.StatusBadRequest,
		`{"target": "x.io", "extra": 1}`:  http.StatusBadRequest,
		`not json`:                        http.StatusBadRequest,
	} {
		if rec := do(t, h, "POST", "/api/targets", body, jsonHeader); rec.Code != want {
			t.Errorf("%s: status %d, want %d", body, rec.Code, want)
		}
	}
	if rec := do(t, h, "POST", "/api/targets", `{"target": "x.io"}`, nil); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("missing content type: %d", rec.Code)
	}

	n.blockAdd = true
	rec := do(t, h, "POST", "/api/targets", `{"target": "192.168.1.1"}`, jsonHeader)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("blocked: status %d", rec.Code)
	}
	if e := decode[errorResponse](t, rec); !e.Blocked || !strings.Contains(e.Error, "Allow private targets") {
		t.Errorf("blocked error = %+v", e)
	}
	if len(cfg.Get().Network.Targets) != 0 {
		t.Error("rejected targets must not be saved")
	}
}

func TestAddTargetRespectsLimit(t *testing.T) {
	var many []config.NetTarget
	for i := 0; i < config.MaxTargets; i++ {
		many = append(many, config.NetTarget{ID: "t" + string(rune('a'+i)), Name: "T", Target: "example.com"})
	}
	h, _, _ := newNetworkServer(t, many...)
	if rec := do(t, h, "POST", "/api/targets", `{"target": "example.org"}`, jsonHeader); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("over the limit: status %d", rec.Code)
	}
}

func TestDeleteTarget(t *testing.T) {
	h, n, cfg := newNetworkServer(t, site, config.NetTarget{ID: "dns", Name: "DNS", Target: "1.1.1.1:53"})
	if rec := do(t, h, "DELETE", "/api/targets/site", "", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if targets := cfg.Get().Network.Targets; len(targets) != 1 || targets[0].ID != "dns" || n.reconfigs != 1 {
		t.Errorf("after delete: %+v", targets)
	}
	if rec := do(t, h, "DELETE", "/api/targets/site", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: %d", rec.Code)
	}
}

func TestTargetHistory(t *testing.T) {
	h, n, _ := newNetworkServer(t, site)
	rec := do(t, h, "GET", "/api/targets/site/history?range=6h", "", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got := decode[TargetHistoryResponse](t, rec)
	if got.Range != "6h" || got.BucketSeconds != 60 || len(got.Points) != 1 || got.UptimePercent == nil || *got.UptimePercent != 75 {
		t.Errorf("history = %+v", got)
	}
	if rec := do(t, h, "GET", "/api/targets/site/history", "", nil); decode[TargetHistoryResponse](t, rec).Range != "24h" {
		t.Error("default range should be 24h")
	}
	if rec := do(t, h, "GET", "/api/targets/site/history?range=2y", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad range: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/api/targets/nope/history", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown target: %d", rec.Code)
	}
	n.historyErr = netwatch.ErrNoHistory
	if rec := do(t, h, "GET", "/api/targets/site/history", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no history: %d", rec.Code)
	}
}

func TestCheckNow(t *testing.T) {
	h, n, _ := newNetworkServer(t, site)
	if rec := do(t, h, "POST", "/api/targets/site/check", "{}", jsonHeader); rec.Code != http.StatusAccepted || n.checked != "site" {
		t.Fatalf("status %d checked %q", rec.Code, n.checked)
	}
	if rec := do(t, h, "POST", "/api/targets/nope/check", "{}", jsonHeader); rec.Code != http.StatusNotFound {
		t.Errorf("unknown: %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/targets/site/check", "", nil); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form post: %d", rec.Code)
	}
}

func TestScan(t *testing.T) {
	h, n, _ := newNetworkServer(t)
	rec := do(t, h, "POST", "/api/scan", `{"target": "https://example.com/x", "checks": ["dns", "ports"], "ports": "22,80-82"}`, jsonHeader)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if got := decode[ScanResponse](t, rec); got.Report.Target.Host != "example.com" || len(got.Report.Notes) != 1 {
		t.Errorf("report = %+v", got.Report)
	}
	req := n.lastScan
	if !req.Checks.DNS || !req.Checks.Ports || req.Checks.HTTP || len(req.Ports) != 4 {
		t.Errorf("scan request = %+v", req)
	}

	// Checks default to all, and ports to the CLI's default list.
	if rec := do(t, h, "POST", "/api/scan", `{"target": "example.com"}`, jsonHeader); rec.Code != 200 {
		t.Fatalf("defaults: status %d", rec.Code)
	}
	if c := n.lastScan.Checks; !c.DNS || !c.Ports || !c.TCP || !c.TLS || !c.HTTP || len(n.lastScan.Ports) != len(probe.DefaultPorts()) {
		t.Errorf("defaults = %+v ports=%v", c, n.lastScan.Ports)
	}

	// Without the ports check, the port spec is ignored rather than rejected.
	if rec := do(t, h, "POST", "/api/scan", `{"target": "example.com", "checks": ["tls"], "ports": "all"}`, jsonHeader); rec.Code != 200 || n.lastScan.Ports != nil {
		t.Errorf("tls only: status %d ports %v", rec.Code, n.lastScan.Ports)
	}
}

func TestScanRejections(t *testing.T) {
	h, n, _ := newNetworkServer(t)
	cases := map[string]int{
		`{"target": "ftp://x"}`:                                          http.StatusBadRequest,
		`{"target": "example.com", "checks": ["banana"]}`:                http.StatusBadRequest,
		`{"target": "example.com", "checks": ["ports"], "ports": "all"}`: http.StatusBadRequest,
		`{"target": "example.com", "checks": ["ports"], "ports": "0"}`:   http.StatusBadRequest,
	}
	for body, want := range cases {
		if rec := do(t, h, "POST", "/api/scan", body, jsonHeader); rec.Code != want {
			t.Errorf("%s: status %d, want %d (%s)", body, rec.Code, want, rec.Body)
		}
	}
	if rec := do(t, h, "POST", "/api/scan", `{"target": "example.com"}`, nil); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form post: %d", rec.Code)
	}

	n.scanErr = netwatch.ErrScanBusy
	if rec := do(t, h, "POST", "/api/scan", `{"target": "example.com"}`, jsonHeader); rec.Code != http.StatusTooManyRequests {
		t.Errorf("busy: %d", rec.Code)
	}
	n.scanErr = &safety.BlockedError{Target: "127.0.0.1", Reason: "it is a loopback address"}
	rec := do(t, h, "POST", "/api/scan", `{"target": "127.0.0.1"}`, jsonHeader)
	if e := decode[errorResponse](t, rec); rec.Code != http.StatusUnprocessableEntity || !e.Blocked {
		t.Errorf("blocked: %d %+v", rec.Code, e)
	}
}

func TestNetworkAlertsAreMergedMostSevereFirst(t *testing.T) {
	h, _, _ := newNetworkServer(t, site)
	sys := decode[SystemResponse](t, do(t, h, "GET", "/api/system", "", nil))
	if len(sys.ActiveAlerts) != 2 || sys.ActiveAlerts[0].Rule != "net_down" || sys.ActiveAlerts[1].Rule != "cpu_usage" {
		t.Errorf("system alerts = %+v", sys.ActiveAlerts)
	}
	alerts := decode[AlertsResponse](t, do(t, h, "GET", "/api/alerts", "", nil))
	if len(alerts.Active) != 2 {
		t.Errorf("alerts page = %+v", alerts.Active)
	}
}

func TestSettingsUpdateReconfiguresNetwork(t *testing.T) {
	h, n, _ := newNetworkServer(t)
	rec := do(t, h, "PUT", "/api/settings", `{"network": {"allowPrivateTargets": true, "checkIntervalSeconds": 30,
		"failuresBeforeAlert": 3, "slowResponseMs": 1500, "certExpiry": {"warningDays": 21, "criticalDays": 7}, "targets": []}}`, jsonHeader)
	if rec.Code != 200 || n.reconfigs != 1 {
		t.Fatalf("status %d reconfigs %d: %s", rec.Code, n.reconfigs, rec.Body)
	}
}

func TestNetworkEndpointsWithoutNetwork(t *testing.T) {
	h, _ := newTestServer(t, &fakeSource{snap: sampleSnapshot()}, nil)
	if rec := do(t, h, "GET", "/api/targets", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("targets: %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/scan", `{"target": "x.io"}`, jsonHeader); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("scan: %d", rec.Code)
	}
}

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"My Site!": "my-site", "  --DNS--  ": "dns", "***": "target", "Café Wi-Fi": "caf-wi-fi",
		strings.Repeat("a", 50): strings.Repeat("a", 32),
	} {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
