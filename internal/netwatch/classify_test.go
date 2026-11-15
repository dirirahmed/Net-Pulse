package netwatch

import (
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func ms(v float64) result.Duration { return result.Duration(v * float64(time.Millisecond)) }

// healthy is a fully successful HTTPS report: 120 ms total response.
func healthy() result.Report {
	return result.Report{
		StartedAt: t0,
		DNS:       &result.DNSResult{Status: result.StatusOK, Duration: ms(12)},
		TCP:       &result.TCPResult{Address: "93.184.215.14:443", Status: result.StatusOK, Duration: ms(20)},
		TLS: &result.TLSResult{Status: result.StatusOK, Verified: true, HandshakeDuration: ms(30),
			Certificates: []result.Certificate{{DaysUntilExpiry: 45}}},
		HTTP: &result.HTTPResult{Status: result.StatusOK, StatusCode: 200, TTFB: ms(90), Duration: ms(120)},
	}
}

func TestClassifyHealthy(t *testing.T) {
	c := Classify(healthy(), "site", 1500)
	if c.Status != models.NetUp || c.Problem != "" {
		t.Fatalf("status=%s problem=%q", c.Status, c.Problem)
	}
	if *c.DNSMs != 12 || *c.ConnectMs != 20 || *c.TLSMs != 30 || *c.TTFBMs != 90 || *c.ResponseMs != 120 {
		t.Errorf("timings = dns %v connect %v tls %v ttfb %v response %v", *c.DNSMs, *c.ConnectMs, *c.TLSMs, *c.TTFBMs, *c.ResponseMs)
	}
	if *c.HTTPStatus != 200 || *c.CertDaysLeft != 45 || !c.Timestamp.Equal(t0) || c.TargetID != "site" {
		t.Errorf("check = %+v", c)
	}
}

func TestClassifyOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*result.Report)
		status  models.NetStatus
		problem string
	}{
		{"dns failure", func(r *result.Report) {
			r.DNS = &result.DNSResult{Status: result.StatusError, Error: &result.ProbeError{Kind: result.ErrKindDNS, Message: "no such host"}}
			r.TCP, r.TLS, r.HTTP = nil, nil, nil
		}, models.NetDown, "DNS lookup failed: no such host"},
		{"connection refused", func(r *result.Report) {
			r.TCP = &result.TCPResult{Address: "1.2.3.4:443", Status: result.StatusClosed, Error: &result.ProbeError{Kind: result.ErrKindRefused, Message: "refused"}}
		}, models.NetDown, "TCP connection to 1.2.3.4:443 failed: refused"},
		{"tls handshake failure", func(r *result.Report) {
			r.TLS = &result.TLSResult{Status: result.StatusError, Error: &result.ProbeError{Kind: result.ErrKindTLS, Message: "handshake failure"}}
		}, models.NetDown, "TLS handshake failed"},
		{"certificate does not verify", func(r *result.Report) {
			bad := &result.ProbeError{Kind: result.ErrKindCertificate, Message: "certificate has expired"}
			r.TLS = &result.TLSResult{Status: result.StatusError, VerifyError: bad, Error: bad, HandshakeDuration: ms(30),
				Certificates: []result.Certificate{{DaysUntilExpiry: -3}}}
			r.HTTP = &result.HTTPResult{Status: result.StatusError, Error: bad}
		}, models.NetDegraded, "TLS certificate is not valid: certificate has expired"},
		{"server error", func(r *result.Report) { r.HTTP.StatusCode = 503 }, models.NetDegraded, "HTTP 503"},
		{"not found is still up", func(r *result.Report) { r.HTTP.StatusCode = 404 }, models.NetUp, ""},
		{"slow", func(r *result.Report) { r.HTTP.Duration = ms(2400) }, models.NetDegraded, "slow response: 2400 ms (limit 1500 ms)"},
		{"http transport error", func(r *result.Report) {
			r.HTTP = &result.HTTPResult{Status: result.StatusTimeout, Error: &result.ProbeError{Kind: result.ErrKindTimeout, Message: "timeout"}}
		}, models.NetDown, "HTTP request failed: timeout"},
		{"down beats degraded", func(r *result.Report) {
			r.HTTP.StatusCode = 503
			r.TLS = &result.TLSResult{Status: result.StatusError, Error: &result.ProbeError{Kind: result.ErrKindTLS, Message: "eof"}}
		}, models.NetDown, "TLS handshake failed: eof"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := healthy()
			tc.mutate(&rep)
			c := Classify(rep, "site", 1500)
			if c.Status != tc.status || !strings.Contains(c.Problem, tc.problem) {
				t.Errorf("got %s %q, want %s containing %q", c.Status, c.Problem, tc.status, tc.problem)
			}
		})
	}
}

func TestClassifyWithoutHTTPUsesConnectTime(t *testing.T) {
	rep := healthy()
	rep.TLS, rep.HTTP = nil, nil
	rep.DNS = &result.DNSResult{Status: result.StatusOK, Literal: true}
	c := Classify(rep, "dns", 1500)
	if c.Status != models.NetUp || c.ResponseMs == nil || *c.ResponseMs != 20 {
		t.Fatalf("status=%s response=%v", c.Status, c.ResponseMs)
	}
	if c.DNSMs != nil {
		t.Error("an IP literal has no DNS lookup time")
	}
	if c.HTTPStatus != nil || c.CertDaysLeft != nil {
		t.Error("HTTP and certificate fields must stay nil when those checks didn't run")
	}
}

func TestClassifyDownHasNoResponseTime(t *testing.T) {
	rep := healthy()
	rep.HTTP = &result.HTTPResult{Status: result.StatusError, Error: &result.ProbeError{Kind: result.ErrKindReset, Message: "reset"}}
	if c := Classify(rep, "site", 1500); c.ResponseMs != nil {
		t.Errorf("response time %v reported for a failed request", *c.ResponseMs)
	}
}
