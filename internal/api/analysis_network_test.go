package api

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dirirahmed/Net-Pulse/internal/ai"
	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/netwatch"
)

func ip(v int) *int                            { return &v }
func fp(v float64) *float64                    { return &v }
func check(c models.NetCheck) *models.NetCheck { return &c }

// Two targets: one named by the user and up, one unnamed (so named after its
// address) and down with a raw error that quotes an IP address.
func networkFixture() *fakeNetwork {
	return &fakeNetwork{
		statuses: []netwatch.TargetStatus{
			{ID: "shop", Name: "My shop", Target: "https://shop.example.com", Status: models.NetUp,
				Last:   check(models.NetCheck{Status: models.NetUp, ResponseMs: fp(120), HTTPStatus: ip(200)}),
				Recent: []models.NetCheck{{CertDaysLeft: ip(5)}, {Status: models.NetUp}}},
			{ID: "api", Name: "api.internal-corp.net:8443", Target: "api.internal-corp.net:8443", Status: models.NetDown, ConsecutiveFailures: 4,
				Last: check(models.NetCheck{Status: models.NetDown, Reason: models.NetReasonConnect,
					Problem: "TCP connection to 10.20.30.40:8443 failed: dial tcp 10.20.30.40:8443: i/o timeout"})},
		},
		alerts: []models.Alert{{ID: "n1", Rule: "net_down", Component: "network", Target: "api.internal-corp.net:8443",
			Severity: models.SeverityCritical, Title: "api.internal-corp.net:8443 is unreachable", Value: 4,
			Reason: "api.internal-corp.net:8443 failed 4 checks in a row. TCP connection to 10.20.30.40:8443 failed: dial tcp 10.20.30.40:8443: i/o timeout"}},
	}
}

func networkAnalysisServer(t *testing.T, n *fakeNetwork, a Assistant) *Server {
	t.Helper()
	cfg := config.NewStore(filepath.Join(t.TempDir(), "config.json"), config.Default())
	n.cfg = cfg
	s := New(&fakeSource{snap: sampleSnapshot(), points: busySeries()}, cfg, nil, nil).WithNetwork(n)
	if a != nil {
		s.WithAssistant(a)
	}
	return s
}

func TestAnalysisIncludesNetworkFindings(t *testing.T) {
	h := networkAnalysisServer(t, networkFixture(), nil).Handler()
	resp := decode[AnalysisResponse](t, do(t, h, "GET", "/api/analysis", "", nil))
	rules := map[string]bool{}
	for _, f := range resp.Analysis.Findings {
		rules[f.Rule] = true
	}
	if !rules["net_down"] || !rules["net_cert_expiry"] || !rules["cpu_bottleneck"] {
		t.Fatalf("rules = %v", rules)
	}
	// The dashboard is local, so it shows the real names.
	for _, f := range resp.Analysis.Findings {
		if f.Rule == "net_down" && f.Target != "api.internal-corp.net:8443" {
			t.Errorf("UI finding target = %q", f.Target)
		}
		if f.Rule == "net_cert_expiry" && !strings.Contains(f.Evidence, "expires in 5 days") {
			t.Errorf("certificate days from an earlier check were not used: %q", f.Evidence)
		}
	}
}

func TestAnalysisNotesWhenNoTargets(t *testing.T) {
	h := networkAnalysisServer(t, &fakeNetwork{statuses: []netwatch.TargetStatus{}}, nil).Handler()
	resp := decode[AnalysisResponse](t, do(t, h, "GET", "/api/analysis", "", nil))
	if !strings.Contains(strings.Join(resp.Analysis.Notes, " "), "No network targets are monitored") {
		t.Errorf("notes = %v", resp.Analysis.Notes)
	}
}

func TestAskNeverSendsMonitoredAddresses(t *testing.T) {
	a := &fakeAssistant{enabled: true}
	h := networkAnalysisServer(t, networkFixture(), a).Handler()
	rec := do(t, h, "POST", "/api/ai/ask", `{"question": "Is it my PC or my internet?"}`, jsonHeader)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	data, _ := json.Marshal(a.got.Data)
	sent := string(data)
	for _, secret := range []string{"api.internal-corp.net", "10.20.30.40", "dial tcp", "shop.example.com"} {
		if strings.Contains(sent, secret) {
			t.Errorf("model data contains %q", secret)
		}
	}
	// A name the user chose is kept; the unnamed target gets a neutral label.
	if !strings.Contains(sent, `"name":"My shop"`) || !strings.Contains(sent, "Monitored target 2") {
		t.Errorf("labels missing from %s", sent)
	}
	var down *ai.NetTargetInfo
	for i := range a.got.Data.NetworkTargets {
		if a.got.Data.NetworkTargets[i].Status == "down" {
			down = &a.got.Data.NetworkTargets[i]
		}
	}
	if down == nil || down.Reason != "connect" || down.ConsecutiveFailures != 4 {
		t.Errorf("down target = %+v", down)
	}
	var alert *ai.AlertInfo
	for i := range a.got.Data.ActiveAlerts {
		if strings.Contains(a.got.Data.ActiveAlerts[i].Title, "Monitored target 2") {
			alert = &a.got.Data.ActiveAlerts[i]
		}
	}
	if alert == nil || alert.Reason != "Monitored target 2 failed 4 checks in a row." {
		t.Errorf("network alert for the model = %+v", alert)
	}
	// The response's own analysis is for the local UI and keeps real names.
	if !strings.Contains(rec.Body.String(), "api.internal-corp.net:8443") {
		t.Error("the local response should keep the real target names")
	}
}

func TestAskWithoutNetworkSendsNoTargets(t *testing.T) {
	a := &fakeAssistant{enabled: true}
	h := newHandler(t, &fakeSource{snap: sampleSnapshot(), points: busySeries()}, a)
	if rec := do(t, h, "POST", "/api/ai/ask", `{"question": "Why is my PC slow?"}`, jsonHeader); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if a.got.Data.NetworkTargets != nil {
		t.Errorf("network targets sent without network monitoring: %+v", a.got.Data.NetworkTargets)
	}
}

func TestRevealsAddress(t *testing.T) {
	for _, c := range []struct {
		name, target string
		want         bool
	}{
		{"My shop", "https://shop.example.com", false},
		{"https://shop.example.com", "https://shop.example.com", true},
		{"shop.example.com", "https://shop.example.com/health", true},
		{"Shop.Example.com backend", "shop.example.com:8443", true},
		{"Cloudflare DNS", "1.1.1.1:53", false},
	} {
		if got := revealsAddress(c.name, c.target); got != c.want {
			t.Errorf("revealsAddress(%q, %q) = %v", c.name, c.target, got)
		}
	}
}
