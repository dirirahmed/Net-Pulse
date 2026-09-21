package engine

import (
	"context"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}
	return port
}

func testOptions(port int) Options {
	opts := DefaultOptions()
	opts.Ports = []int{port}
	opts.Concurrency = 2
	opts.DialTimeout = 2 * time.Second
	opts.HTTPTimeout = 5 * time.Second
	opts.TLSTimeout = 5 * time.Second
	opts.TotalTimeout = 20 * time.Second
	return opts
}

func TestRunAgainstHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	report, err := RunTarget(context.Background(), srv.URL, testOptions(serverPort(t, srv)))
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}

	if report.DNS == nil || report.DNS.Status != result.StatusOK {
		t.Fatalf("dns = %+v", report.DNS)
	}
	if !report.DNS.Literal {
		t.Error("expected the loopback IP to be treated as a literal")
	}
	if report.TCP == nil || report.TCP.Status != result.StatusOK {
		t.Fatalf("tcp = %+v", report.TCP)
	}
	if report.Ports == nil || report.Ports.Open != 1 {
		t.Fatalf("ports = %+v", report.Ports)
	}
	if report.HTTP == nil || report.HTTP.StatusCode != http.StatusOK {
		t.Fatalf("http = %+v", report.HTTP)
	}
	if report.TLS != nil {
		t.Error("TLS should be skipped for an http:// target")
	}
	if report.Duration <= 0 {
		t.Error("expected a non-zero report duration")
	}
}

func TestRunAgainstHTTPSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// The port scan opens and closes a TCP connection without a handshake,
	// which the test server would otherwise log as an error.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	opts := testOptions(serverPort(t, srv))
	opts.RootCAs = pool

	report, err := RunTarget(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}

	if report.TLS == nil {
		t.Fatal("expected TLS results for an https:// target")
	}
	if report.TLS.Status != result.StatusOK || !report.TLS.Verified {
		t.Fatalf("tls = %+v", report.TLS)
	}
	if len(report.TLS.Certificates) == 0 {
		t.Error("expected certificate details")
	}
	if report.HTTP == nil || report.HTTP.StatusCode != http.StatusOK {
		t.Fatalf("http = %+v", report.HTTP)
	}
}

func TestRunSkipsDependentChecksWhenDNSFails(t *testing.T) {
	opts := DefaultOptions()
	opts.DNSTimeout = 2 * time.Second
	opts.Ports = []int{80}

	report, err := RunTarget(context.Background(), "netpulse-does-not-exist.invalid", opts)
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}

	if report.DNS == nil || report.DNS.Status == result.StatusOK {
		t.Skip("this environment resolved a .invalid name, skipping")
	}
	if report.TCP != nil || report.TLS != nil || report.HTTP != nil || report.Ports != nil {
		t.Error("dependent checks should be skipped when DNS fails")
	}
	if len(report.Notes) == 0 {
		t.Error("expected a note explaining the skip")
	}
}

func TestRunSelectedChecksOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	opts := testOptions(serverPort(t, srv))
	opts.Checks = Checks{DNS: true, TCP: true}

	report, err := RunTarget(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}
	if report.DNS == nil || report.TCP == nil {
		t.Fatal("expected DNS and TCP results")
	}
	if report.Ports != nil || report.HTTP != nil || report.TLS != nil {
		t.Error("only the selected checks should run")
	}
}

func TestRunTargetRejectsBadTarget(t *testing.T) {
	if _, err := RunTarget(context.Background(), "ftp://example.com", DefaultOptions()); err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
}
