package probe

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func newTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Probes close connections without sending a request, which the test server
	// would otherwise log as a handshake error.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTLSHandshakeVerified(t *testing.T) {
	srv := newTLSServer(t)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	res := TLSHandshake(context.Background(), srv.Listener.Addr().String(), TLSOptions{
		Timeout: 5 * time.Second,
		RootCAs: pool,
	})

	if res.Status != result.StatusOK {
		t.Fatalf("status = %q (%v)", res.Status, res.Error)
	}
	if !res.Verified {
		t.Error("expected the chain to verify against the supplied root")
	}
	if res.Version == "" || res.CipherSuite == "" {
		t.Errorf("expected version and cipher to be recorded, got %q / %q", res.Version, res.CipherSuite)
	}
	if len(res.Certificates) == 0 {
		t.Fatal("expected certificate details")
	}
	if res.ExpiresAt.IsZero() {
		t.Error("expected a leaf expiry time")
	}
	if res.HandshakeDuration < 0 {
		t.Errorf("handshake duration = %s, must not be negative", res.HandshakeDuration)
	}
}

func TestTLSHandshakeUntrustedCertificate(t *testing.T) {
	srv := newTLSServer(t)

	// An empty pool trusts nothing, so the self-signed test certificate must
	// fail validation rather than be waved through.
	res := TLSHandshake(context.Background(), srv.Listener.Addr().String(), TLSOptions{
		Timeout:                5 * time.Second,
		RootCAs:                x509.NewCertPool(),
		CollectOnVerifyFailure: true,
	})

	if res.Status == result.StatusOK {
		t.Fatal("an untrusted certificate must not be reported as ok")
	}
	if res.Verified {
		t.Fatal("Verified must stay false when validation fails")
	}
	if res.VerifyError == nil || res.VerifyError.Kind != result.ErrKindCertificate {
		t.Fatalf("verify error = %v, want a certificate kind", res.VerifyError)
	}
	if len(res.Certificates) == 0 {
		t.Error("expected certificate details to be collected for diagnosis")
	}
}

func TestTLSHandshakeConnectionRefused(t *testing.T) {
	res := TLSHandshake(context.Background(), closedAddress(t), TLSOptions{Timeout: 2 * time.Second})
	if res.Status != result.StatusError {
		t.Fatalf("status = %q, want error", res.Status)
	}
	if res.Error == nil {
		t.Fatal("expected a structured error")
	}
	if res.Verified {
		t.Fatal("Verified must be false when no handshake happened")
	}
}

func TestSummarizeCertificateExpiry(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	expired := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "old.example.com"},
		Issuer:       pkix.Name{CommonName: "old.example.com"},
		SerialNumber: big.NewInt(1),
		NotBefore:    now.AddDate(-2, 0, 0),
		NotAfter:     now.AddDate(0, 0, -10),
	}
	got := SummarizeCertificate(expired, now)
	if !got.Expired {
		t.Error("expected Expired to be true")
	}
	if got.DaysUntilExpiry > 0 {
		t.Errorf("DaysUntilExpiry = %d, want a negative value", got.DaysUntilExpiry)
	}
	if !got.SelfSigned {
		t.Error("expected SelfSigned to be true when subject equals issuer")
	}

	valid := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "new.example.com"},
		Issuer:       pkix.Name{CommonName: "Example CA"},
		SerialNumber: big.NewInt(2),
		NotBefore:    now.AddDate(0, 0, -1),
		NotAfter:     now.AddDate(0, 0, 30),
	}
	got = SummarizeCertificate(valid, now)
	if got.Expired {
		t.Error("expected Expired to be false")
	}
	if got.DaysUntilExpiry < 29 || got.DaysUntilExpiry > 30 {
		t.Errorf("DaysUntilExpiry = %d, want about 30", got.DaysUntilExpiry)
	}
	if got.SelfSigned {
		t.Error("expected SelfSigned to be false")
	}
}

func TestTLSVersionName(t *testing.T) {
	if got := TLSVersionName(0x0304); got != "TLS 1.3" {
		t.Errorf("TLSVersionName(0x0304) = %q", got)
	}
	if got := TLSVersionName(0x0000); got == "" {
		t.Error("unknown versions should still render something")
	}
}
