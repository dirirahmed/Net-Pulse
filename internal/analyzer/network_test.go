package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/models"
)

func fptr(v float64) *float64 { return &v }
func iptr(v int) *int         { return &v }

func netAnalyze(targets []NetTarget) PerformanceReport {
	return AnalyzePerformance(PerformanceInput{
		Now: t0.Add(5 * time.Minute), Points: series(10, 30, nil), Processes: []models.Process{},
		DiskFree: config.Default().Thresholds.DiskFreePercent,
		Network:  targets, NetworkSettings: config.Default().Network,
	})
}

func up(name string) NetTarget {
	return NetTarget{Name: name, Status: models.NetUp, ResponseMs: fptr(80), HTTPStatus: iptr(200)}
}

func TestNetworkAbsentOrEmpty(t *testing.T) {
	r := AnalyzePerformance(PerformanceInput{Now: t0, Points: series(10, 30, nil), Processes: []models.Process{}})
	for _, n := range r.Notes {
		if strings.Contains(n, "network targets") {
			t.Error("no note expected when network monitoring isn't wired in")
		}
	}
	r = netAnalyze([]NetTarget{})
	if len(r.Findings) != 0 || !strings.Contains(strings.Join(r.Notes, " "), "No network targets are monitored") {
		t.Errorf("empty targets: findings=%+v notes=%v", r.Findings, r.Notes)
	}
}

func TestHealthyTargetsProduceNoFindings(t *testing.T) {
	r := netAnalyze([]NetTarget{up("Site"), up("API")})
	if len(r.Findings) != 0 || r.Status != StatusOK {
		t.Fatalf("findings=%+v status=%s", r.Findings, r.Status)
	}
}

func TestOneTargetDownBlamesTheService(t *testing.T) {
	down := NetTarget{Name: "API", Status: models.NetDown, Reason: models.NetReasonConnect, ConsecutiveFailures: 3}
	r := netAnalyze([]NetTarget{up("Site"), down})
	f := findRule(r, "net_down")
	if f == nil || f.Severity != models.SeverityCritical || f.Target != "API" {
		t.Fatalf("finding = %+v", f)
	}
	if !strings.Contains(f.Evidence, "failed its last 3 checks: the connection was refused or timed out") {
		t.Errorf("evidence = %q", f.Evidence)
	}
	if !strings.Contains(f.Explanation, "this PC's connection is working") {
		t.Errorf("explanation should rule out this PC: %q", f.Explanation)
	}
	if !strings.Contains(r.Summary, "Most important: API is unreachable") || !strings.Contains(r.Summary, "The PC itself looks fine") {
		t.Errorf("summary = %q", r.Summary)
	}
}

func TestEarlyFailureIsOnlyAWarning(t *testing.T) {
	down := NetTarget{Name: "API", Status: models.NetDown, Reason: models.NetReasonHTTP, ConsecutiveFailures: 1}
	f := findRule(netAnalyze([]NetTarget{down}), "net_down")
	if f == nil || f.Severity != models.SeverityWarning || !strings.Contains(f.Evidence, "failed its last check:") {
		t.Fatalf("finding = %+v", f)
	}
}

func TestEverythingDownBlamesTheConnection(t *testing.T) {
	r := netAnalyze([]NetTarget{
		{Name: "Site", Status: models.NetDown, Reason: models.NetReasonDNS, ConsecutiveFailures: 2},
		{Name: "API", Status: models.NetDown, Reason: models.NetReasonDNS, ConsecutiveFailures: 2},
		{Name: "Router", Status: models.NetBlocked, Reason: models.NetReasonBlocked},
	})
	f := findRule(r, "net_all_down")
	if f == nil || f.Severity != models.SeverityCritical || !strings.Contains(f.Explanation, "DNS") {
		t.Fatalf("finding = %+v", f)
	}
	if findRule(r, "net_down") != nil {
		t.Error("per-target down findings should be folded into the all-down finding")
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "1 monitored target(s) point at private or local addresses") {
		t.Errorf("notes = %v", r.Notes)
	}
}

func TestDegradedFindings(t *testing.T) {
	r := netAnalyze([]NetTarget{
		{Name: "Slow", Status: models.NetDegraded, Reason: models.NetReasonSlow, ResponseMs: fptr(2400)},
		{Name: "Broken", Status: models.NetDegraded, Reason: models.NetReasonServerError, HTTPStatus: iptr(503)},
		{Name: "BadCert", Status: models.NetDegraded, Reason: models.NetReasonCertificate},
	})
	if f := findRule(r, "net_slow"); f == nil || !strings.Contains(f.Evidence, "took 2400 ms; the limit is 1500 ms") {
		t.Errorf("slow = %+v", f)
	}
	if f := findRule(r, "net_server_error"); f == nil || !strings.Contains(f.Evidence, "HTTP 503") || f.Value != 503 {
		t.Errorf("server error = %+v", f)
	}
	if f := findRule(r, "net_cert_invalid"); f == nil || f.Severity != models.SeverityWarning {
		t.Errorf("cert invalid = %+v", f)
	}
}

func TestCertificateExpiry(t *testing.T) {
	soon := up("Site")
	soon.CertDaysLeft = iptr(10)
	if f := findRule(netAnalyze([]NetTarget{soon}), "net_cert_expiry"); f == nil || f.Severity != models.SeverityWarning || !strings.Contains(f.Evidence, "expires in 10 days") {
		t.Errorf("warning = %+v", f)
	}
	soon.CertDaysLeft = iptr(-2)
	if f := findRule(netAnalyze([]NetTarget{soon}), "net_cert_expiry"); f == nil || f.Severity != models.SeverityCritical || !strings.Contains(f.Title, "has expired") {
		t.Errorf("expired = %+v", f)
	}
	soon.CertDaysLeft = iptr(60)
	if f := findRule(netAnalyze([]NetTarget{soon}), "net_cert_expiry"); f != nil {
		t.Errorf("60 days should be fine: %+v", f)
	}
}

func TestUptimeInfoNeedsEnoughChecks(t *testing.T) {
	flaky := up("Site")
	flaky.Uptime24h, flaky.Checks24h = fptr(96.5), 200
	f := findRule(netAnalyze([]NetTarget{flaky}), "net_uptime")
	if f == nil || f.Severity != models.SeverityInfo || !strings.Contains(f.Evidence, "96.5% of 200 checks") {
		t.Fatalf("uptime = %+v", f)
	}
	flaky.Checks24h = 5
	if findRule(netAnalyze([]NetTarget{flaky}), "net_uptime") != nil {
		t.Error("5 checks are too few to judge uptime")
	}
}

func TestNetworkEvidenceNeverContainsRawErrors(t *testing.T) {
	// Only names and coarse reasons are used, so nothing below can leak.
	r := netAnalyze([]NetTarget{
		{Name: "API", Status: models.NetDown, Reason: models.NetReasonConnect, ConsecutiveFailures: 3},
		up("Site"),
	})
	for _, f := range r.Findings {
		for _, text := range []string{f.Title, f.Evidence, f.Explanation, f.Recommendation} {
			if strings.Contains(text, "dial tcp") || strings.Contains(text, "127.0.0.1") {
				t.Errorf("raw error text in finding: %q", text)
			}
		}
	}
}

func TestPCFindingsKeepTheirSummary(t *testing.T) {
	down := NetTarget{Name: "API", Status: models.NetDown, Reason: models.NetReasonConnect, ConsecutiveFailures: 3}
	r := AnalyzePerformance(PerformanceInput{
		Now: t0.Add(5 * time.Minute), Points: series(97, 30, nil), Processes: []models.Process{},
		Network: []NetTarget{up("Site"), down}, NetworkSettings: config.Default().Network,
	})
	if strings.Contains(r.Summary, "PC itself looks fine") {
		t.Errorf("summary claims the PC is fine with CPU at 97%%: %q", r.Summary)
	}
	if r.Findings[0].Severity != models.SeverityCritical {
		t.Error("findings must stay sorted most severe first")
	}
}
