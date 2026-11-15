package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/safety"
)

func newDemoServer(t *testing.T) (http.Handler, *fakeNetwork, *config.Store) {
	t.Helper()
	c := config.Default()
	c.Network.Targets = []config.NetTarget{site}
	cfg := config.NewStore(filepath.Join(t.TempDir(), "config.json"), c)
	n := &fakeNetwork{cfg: cfg}
	a := &fakeAssistant{enabled: true}
	h := New(&fakeSource{snap: sampleSnapshot(), points: busySeries()}, cfg, nil, nil).
		WithAssistant(a).WithNetwork(n).WithDemo(true).Handler()
	return h, n, cfg
}

func TestDemoIsReadOnly(t *testing.T) {
	h, n, cfg := newDemoServer(t)
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/settings", `{"retentionDays": 3}`},
		{"POST", "/api/targets", `{"target": "example.org"}`},
		{"DELETE", "/api/targets/site", ""},
	} {
		rec := do(t, h, c.method, c.path, c.body, jsonHeader)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: status %d, want 403", c.method, c.path, rec.Code)
		}
		if e := decode[errorResponse](t, rec); !e.Demo || !strings.Contains(e.Error, "read-only") {
			t.Errorf("%s %s: error = %+v", c.method, c.path, e)
		}
	}
	if got := cfg.Get(); got.RetentionDays != 7 || len(got.Network.Targets) != 1 || n.reconfigs != 0 {
		t.Errorf("demo config changed: retention %d, targets %d", got.RetentionDays, len(got.Network.Targets))
	}
	// Reading still works, and tells the UI it is the demo.
	if s := decode[SettingsResponse](t, do(t, h, "GET", "/api/settings", "", nil)); !s.Demo {
		t.Error("settings should report demo mode")
	}
	if rec := do(t, h, "POST", "/api/targets/site/check", "{}", jsonHeader); rec.Code != http.StatusAccepted {
		t.Errorf("check now should still work in the demo: %d", rec.Code)
	}
}

func TestDemoDisablesAskPulseEvenWithAKey(t *testing.T) {
	h, _, _ := newDemoServer(t)
	resp := decode[AnalysisResponse](t, do(t, h, "GET", "/api/analysis", "", nil))
	if resp.AI.Enabled || !strings.Contains(resp.AI.Reason, "live demo") {
		t.Errorf("ai status = %+v", resp.AI)
	}
	if rec := do(t, h, "POST", "/api/ai/ask", `{"question": "hi"}`, jsonHeader); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("ask: status %d", rec.Code)
	}
}

func TestDemoAcceptsAnyHostName(t *testing.T) {
	h, _, _ := newDemoServer(t)
	req := httptest.NewRequest("GET", "/api/settings", nil)
	req.Host = "netpulse-demo.onrender.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("public host name rejected in demo mode: %d", rec.Code)
	}
}

func TestDemoScanLimits(t *testing.T) {
	h, _, _ := newDemoServer(t)
	if rec := do(t, h, "POST", "/api/scan", `{"target": "example.com", "checks": ["ports"], "ports": "1-100"}`, jsonHeader); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "at most 64") {
		t.Errorf("port cap: %d %s", rec.Code, rec.Body)
	}
	ok := 0
	for i := 0; i < demoScansPerMinute+3; i++ {
		rec := do(t, h, "POST", "/api/scan", `{"target": "example.com", "checks": ["dns"]}`, jsonHeader)
		switch rec.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			if !strings.Contains(rec.Body.String(), "scans a minute") {
				t.Errorf("429 body: %s", rec.Body)
			}
		default:
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
	}
	if ok != demoScansPerMinute {
		t.Errorf("%d scans allowed in a burst, want %d", ok, demoScansPerMinute)
	}
}

func TestDemoBlockedMessageHasNoSettingsHint(t *testing.T) {
	h, n, _ := newDemoServer(t)
	n.scanErr = &safety.BlockedError{Target: "169.254.169.254", Reason: "it is link-local"}
	e := decode[errorResponse](t, do(t, h, "POST", "/api/scan", `{"target": "169.254.169.254"}`, jsonHeader))
	if !e.Blocked || !e.Demo || strings.Contains(e.Error, "Settings") || !strings.Contains(e.Error, "live demo never reaches") {
		t.Errorf("demo blocked error = %+v", e)
	}
}

func TestHealthzAnswersBeforeFirstSample(t *testing.T) {
	h, _ := newTestServer(t, &fakeSource{}, nil)
	if rec := do(t, h, "GET", "/healthz", "", nil); rec.Code != 200 {
		t.Errorf("healthz: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/api/health", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("api/health before the first sample: %d", rec.Code)
	}
}

func TestRateLimiterRefills(t *testing.T) {
	now := time.Unix(0, 0)
	l := newRateLimiter(2, time.Minute)
	l.now = func() time.Time { return now }
	if !l.allow() || !l.allow() || l.allow() {
		t.Fatal("burst of 2 expected")
	}
	now = now.Add(30 * time.Second) // one token back
	if !l.allow() || l.allow() {
		t.Error("expected exactly one refilled token after 30 s")
	}
}

func TestLocalModeStillRejectsForeignHosts(t *testing.T) {
	h, _ := newTestServer(t, &fakeSource{snap: sampleSnapshot()}, nil)
	req := httptest.NewRequest("GET", "/api/settings", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("foreign host outside demo mode: %d", rec.Code)
	}
}
