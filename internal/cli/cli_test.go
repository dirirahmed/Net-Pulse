package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func TestParseChecks(t *testing.T) {
	all, err := parseChecks("all")
	if err != nil || all != engine.All() {
		t.Fatalf("parseChecks(all) = %+v, %v", all, err)
	}

	some, err := parseChecks("dns, tcp")
	if err != nil {
		t.Fatalf("parseChecks: %v", err)
	}
	if !some.DNS || !some.TCP || some.HTTP || some.TLS || some.Ports {
		t.Fatalf("parseChecks(dns,tcp) = %+v", some)
	}

	if _, err := parseChecks("banana"); err == nil {
		t.Error("expected an error for an unknown check")
	}
	if _, err := parseChecks(",,"); err == nil {
		t.Error("expected an error when nothing is selected")
	}
}

func TestRunJSONOutput(t *testing.T) {
	var out bytes.Buffer

	err := Run(context.Background(), []string{"-json", "-checks", "dns", "127.0.0.1"}, &out, io.Discard)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var report result.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out.String())
	}
	if report.Target.Host != "127.0.0.1" {
		t.Errorf("target host = %q", report.Target.Host)
	}
	if report.DNS == nil || report.DNS.Status != result.StatusOK {
		t.Fatalf("dns = %+v", report.DNS)
	}
	if report.TCP != nil {
		t.Error("only the dns check was requested")
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	cases := [][]string{
		{"-ports", "banana", "127.0.0.1"},
		{"-checks", "banana", "127.0.0.1"},
		{"-concurrency", "0", "127.0.0.1"},
		{"127.0.0.1", "8.8.8.8"},
		{"-checks", "dns", "ftp://example.com"},
	}

	for _, args := range cases {
		if err := Run(context.Background(), args, io.Discard, io.Discard); err == nil {
			t.Errorf("Run(%v) succeeded, want an error", args)
		}
	}
}

func TestRenderSummary(t *testing.T) {
	now := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

	rep := result.Report{
		Target:    result.Target{Raw: "example.com", Host: "example.com"},
		StartedAt: now,
		Duration:  result.Duration(1500 * time.Millisecond),
		DNS: &result.DNSResult{
			Host:      "example.com",
			Status:    result.StatusOK,
			Addresses: []string{"93.184.216.34"},
			Primary:   "93.184.216.34",
			Duration:  result.Duration(12 * time.Millisecond),
		},
		TCP: &result.TCPResult{
			Address:  "93.184.216.34:443",
			Status:   result.StatusOK,
			Duration: result.Duration(24 * time.Millisecond),
		},
		TLS: &result.TLSResult{
			Address:           "93.184.216.34:443",
			Status:            result.StatusOK,
			Verified:          true,
			Version:           "TLS 1.3",
			CipherSuite:       "TLS_AES_128_GCM_SHA256",
			HandshakeDuration: result.Duration(40 * time.Millisecond),
			Certificates: []result.Certificate{{
				Subject:         "CN=example.com",
				Issuer:          "CN=Example CA",
				NotAfter:        now.AddDate(0, 0, 60),
				DaysUntilExpiry: 60,
			}},
		},
		HTTP: &result.HTTPResult{
			URL:        "https://example.com/",
			Method:     "GET",
			Status:     result.StatusOK,
			StatusCode: 200,
			Duration:   result.Duration(88 * time.Millisecond),
			TTFB:       result.Duration(61 * time.Millisecond),
			Headers:    map[string]string{"Server": "ECS"},
		},
		Ports: &result.PortScanResult{
			Host:    "example.com",
			Address: "93.184.216.34",
			Scanned: 2,
			Open:    1,
			Results: []result.PortResult{
				{Port: 443, Service: "HTTPS", Status: result.StatusOpen},
				{Port: 22, Service: "SSH", Status: result.StatusClosed},
			},
		},
		Notes: []string{"example note"},
	}

	var out bytes.Buffer
	Render(&out, rep, false)
	got := out.String()

	for _, want := range []string{"[DNS]", "[TCP]", "[TLS]", "[HTTP]", "[PORTS]", "93.184.216.34", "TLS 1.3", "200", "443", "example note"} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered output is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "SSH") {
		t.Error("closed ports should be hidden unless -show-closed is set")
	}

	out.Reset()
	Render(&out, rep, true)
	if !strings.Contains(out.String(), "SSH") {
		t.Error("closed ports should be listed with showClosed set")
	}
}

func TestRenderExpiredCertificate(t *testing.T) {
	rep := result.Report{
		Target: result.Target{Raw: "old.example.com", Host: "old.example.com"},
		TLS: &result.TLSResult{
			Status:   result.StatusError,
			Verified: false,
			VerifyError: &result.ProbeError{
				Kind:    result.ErrKindCertificate,
				Message: "x509: certificate has expired",
			},
			Certificates: []result.Certificate{{
				Subject:         "CN=old.example.com",
				Issuer:          "CN=old.example.com",
				Expired:         true,
				DaysUntilExpiry: -12,
			}},
		},
	}

	var out bytes.Buffer
	Render(&out, rep, false)
	got := out.String()

	if !strings.Contains(got, "EXPIRED 12 days ago") {
		t.Errorf("expected an expiry warning:\n%s", got)
	}
	if !strings.Contains(got, "verified:  false") {
		t.Errorf("expected the verification result to be shown:\n%s", got)
	}
}
