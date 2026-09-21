package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// TLSOptions configures a handshake.
type TLSOptions struct {
	Timeout    time.Duration
	ServerName string
	RootCAs    *x509.CertPool
	NextProtos []string
	Dialer     *net.Dialer

	// CollectOnVerifyFailure repeats the handshake without verification *only*
	// to read the certificate the server presented. The result is still
	// reported as a failure: Verified stays false and VerifyError is kept.
	CollectOnVerifyFailure bool
}

type handshakeOutcome struct {
	state tls.ConnectionState
	dial  time.Duration
	shake time.Duration
}

// TLSHandshake performs a real, verifying TLS handshake and records what the
// server negotiated and presented.
func TLSHandshake(ctx context.Context, address string, opts TLSOptions) result.TLSResult {
	res := result.TLSResult{Address: address}

	serverName := opts.ServerName
	if serverName == "" {
		if host, _, err := net.SplitHostPort(address); err == nil {
			serverName = host
		}
	}
	res.ServerName = serverName

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	out, err := handshake(ctx, address, serverName, opts, false)
	res.DialDuration = result.Duration(out.dial)
	res.HandshakeDuration = result.Duration(out.shake)

	if err == nil {
		res.Status = result.StatusOK
		res.Verified = true
		fillTLSState(&res, out.state)
		return res
	}

	res.Error = Classify(err)
	res.Status = statusForProbe(res.Error)
	if res.Error.Kind != result.ErrKindCertificate {
		return res
	}

	// The connection worked but the chain did not validate. Record that, then
	// optionally look at the certificate so the operator can see why.
	res.VerifyError = res.Error
	res.Verified = false
	if !opts.CollectOnVerifyFailure {
		return res
	}
	if out2, err2 := handshake(ctx, address, serverName, opts, true); err2 == nil {
		fillTLSState(&res, out2.state)
	}
	return res
}

func handshake(ctx context.Context, address, serverName string, opts TLSOptions, skipVerify bool) (handshakeOutcome, error) {
	var out handshakeOutcome

	dialStart := time.Now()
	conn, err := dial(ctx, address, opts.Timeout, opts.Dialer)
	out.dial = time.Since(dialStart)
	if err != nil {
		return out, err
	}
	defer conn.Close()

	cfg := &tls.Config{
		ServerName: serverName,
		RootCAs:    opts.RootCAs,
		NextProtos: opts.NextProtos,
		// Only ever true on the diagnostic re-probe above, never on the probe
		// whose result is reported as a success.
		InsecureSkipVerify: skipVerify,
	}

	tlsConn := tls.Client(conn, cfg)
	shakeStart := time.Now()
	err = tlsConn.HandshakeContext(ctx)
	out.shake = time.Since(shakeStart)
	if err != nil {
		return out, err
	}
	out.state = tlsConn.ConnectionState()
	return out, nil
}

func fillTLSState(res *result.TLSResult, state tls.ConnectionState) {
	res.Version = TLSVersionName(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	res.ALPN = state.NegotiatedProtocol

	now := time.Now()
	res.Certificates = nil
	for _, cert := range state.PeerCertificates {
		res.Certificates = append(res.Certificates, SummarizeCertificate(cert, now))
	}
	if len(res.Certificates) > 0 {
		leaf := res.Certificates[0]
		res.ExpiresAt = leaf.NotAfter
		res.DaysUntilExpiry = leaf.DaysUntilExpiry
		res.Expired = leaf.Expired
	}
}

// SummarizeCertificate reduces an x509 certificate to the fields worth storing.
func SummarizeCertificate(cert *x509.Certificate, now time.Time) result.Certificate {
	c := result.Certificate{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		CommonName:         cert.Subject.CommonName,
		DNSNames:           cert.DNSNames,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsCA:               cert.IsCA,
	}
	if cert.SerialNumber != nil {
		c.SerialNumber = cert.SerialNumber.String()
	}
	c.SelfSigned = c.Subject == c.Issuer
	c.Expired = now.After(cert.NotAfter)
	c.NotYetValid = now.Before(cert.NotBefore)
	c.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)
	return c
}

// TLSVersionName renders a tls.ConnectionState version number.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
