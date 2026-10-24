package engine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
)

// TestOptionsDialerIsUsedByEveryProbe guards the wiring between Options.Dialer
// and the probe calls inside Run. A caller that cannot trust the target relies
// on that dialer's Control hook to refuse private addresses, so a probe that
// quietly dials with its own dialer would be a hole rather than a cosmetic
// bug. Removing any of the four assignments in Run fails this test.
func TestOptionsDialerIsUsedByEveryProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var dials int64
	opts := testOptions(serverPort(t, srv))
	opts.Checks = Checks{Ports: true, TCP: true, HTTP: true}
	opts.Dialer = &net.Dialer{
		Control: func(_, _ string, _ syscall.RawConn) error {
			atomic.AddInt64(&dials, 1)
			return nil
		},
	}

	report, err := RunTarget(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}

	// One dial for the port scan, one for TCP, one for HTTP.
	if got := atomic.LoadInt64(&dials); got < 3 {
		t.Fatalf("the supplied dialer was used %d times, want at least 3: "+
			"a probe is dialing without it", got)
	}
	if report.HTTP == nil || report.HTTP.StatusCode != http.StatusOK {
		t.Errorf("http result = %+v", report.HTTP)
	}
}

// TestOptionsDialerRefusalStopsProbes checks the direction that matters: when
// the dialer refuses, the probes report failure rather than connecting anyway.
func TestOptionsDialerRefusalStopsProbes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	refused := func(_, _ string, _ syscall.RawConn) error {
		return &net.AddrError{Err: "refused by policy", Addr: "test"}
	}

	opts := testOptions(serverPort(t, srv))
	opts.Checks = Checks{TCP: true, HTTP: true}
	opts.Dialer = &net.Dialer{Control: refused}

	report, err := RunTarget(context.Background(), srv.URL, opts)
	if err != nil {
		t.Fatalf("RunTarget: %v", err)
	}

	if report.TCP == nil {
		t.Fatal("expected a TCP result")
	}
	if report.TCP.Error == nil {
		t.Error("TCP connected despite the dialer refusing")
	}
	if report.HTTP == nil {
		t.Fatal("expected an HTTP result")
	}
	if report.HTTP.StatusCode != 0 {
		t.Errorf("HTTP got status %d despite the dialer refusing", report.HTTP.StatusCode)
	}
}
