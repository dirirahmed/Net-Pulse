package netwatch

import (
	"fmt"
	"strings"

	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// Classify turns one diagnostics report into a check result.
//
//   - down: DNS, the TCP connection, the TLS handshake or the HTTP request failed
//   - degraded: it answered, but with a 5xx, a certificate that doesn't
//     validate, or slower than slowMs
//   - up: everything that ran succeeded
//
// A 4xx is still up: the server is working and answered. Only the first
// problem of the worst status is kept as the one-line reason.
func Classify(rep result.Report, targetID string, slowMs int) models.NetCheck {
	c := models.NetCheck{TargetID: targetID, Timestamp: rep.StartedAt.UTC(), Status: models.NetUp}
	mark := func(s models.NetStatus, reason, format string, args ...any) {
		if rank(s) > rank(c.Status) {
			c.Status, c.Reason, c.Problem = s, reason, fmt.Sprintf(format, args...)
		}
	}

	if d := rep.DNS; d != nil {
		if !d.Literal {
			c.DNSMs = millis(d.Duration)
		}
		if d.Status != result.StatusOK {
			mark(models.NetDown, models.NetReasonDNS, "DNS lookup failed: %s", errText(d.Error))
		}
	}

	if t := rep.TCP; t != nil {
		if t.Status == result.StatusOK {
			c.ConnectMs = millis(t.Duration)
		} else {
			mark(models.NetDown, models.NetReasonConnect, "TCP connection to %s failed: %s", t.Address, errText(t.Error))
		}
	}

	certFailed := false
	if t := rep.TLS; t != nil {
		if len(t.Certificates) > 0 {
			days := t.Certificates[0].DaysUntilExpiry
			c.CertDaysLeft = &days
		}
		switch {
		case t.Status == result.StatusOK:
			c.TLSMs = millis(t.HandshakeDuration)
		case t.VerifyError != nil:
			// The handshake itself worked; the chain didn't validate.
			certFailed = true
			c.TLSMs = millis(t.HandshakeDuration)
			mark(models.NetDegraded, models.NetReasonCertificate, "TLS certificate is not valid: %s", errText(t.VerifyError))
		default:
			mark(models.NetDown, models.NetReasonTLSHandshake, "TLS handshake failed: %s", errText(t.Error))
		}
	}

	if h := rep.HTTP; h != nil {
		switch {
		case h.Status == result.StatusOK:
			code := h.StatusCode
			c.HTTPStatus = &code
			c.TTFBMs = millis(h.TTFB)
			c.ResponseMs = millis(h.Duration)
			if code >= 500 {
				mark(models.NetDegraded, models.NetReasonServerError, "the server answered HTTP %d", code)
			}
		case h.Error != nil && h.Error.Kind == result.ErrKindCertificate:
			// Same root cause as a TLS verify failure, which may already be
			// recorded; on its own (for example after a redirect to another
			// host) it is still a certificate problem, not an outage.
			if !certFailed {
				mark(models.NetDegraded, models.NetReasonCertificate, "TLS certificate is not valid: %s", errText(h.Error))
			}
		default:
			mark(models.NetDown, models.NetReasonHTTP, "HTTP request failed: %s", errText(h.Error))
		}
	}

	// Without an HTTP answer, the TCP connect time is the response time.
	if c.ResponseMs == nil && c.Status != models.NetDown {
		c.ResponseMs = c.ConnectMs
	}
	if c.ResponseMs != nil && slowMs > 0 && *c.ResponseMs >= float64(slowMs) {
		mark(models.NetDegraded, models.NetReasonSlow, "slow response: %.0f ms (limit %d ms)", *c.ResponseMs, slowMs)
	}
	return c
}

func rank(s models.NetStatus) int {
	switch s {
	case models.NetDown:
		return 2
	case models.NetDegraded:
		return 1
	}
	return 0
}

func millis(d result.Duration) *float64 {
	v := float64(int64(d.Millis()*10+0.5)) / 10
	return &v
}

func errText(e *result.ProbeError) string {
	if e == nil {
		return "unknown error"
	}
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return string(e.Kind)
	}
	return msg
}
