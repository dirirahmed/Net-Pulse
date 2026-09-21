package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// Classify turns a network error into a serialisable ProbeError.
func Classify(err error) *result.ProbeError {
	if err == nil {
		return nil
	}
	return &result.ProbeError{Kind: classifyKind(err), Message: err.Error()}
}

func classifyKind(err error) result.ErrorKind {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err) {
		return result.ErrKindTimeout
	}
	if errors.Is(err, context.Canceled) {
		return result.ErrKindCanceled
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout {
			return result.ErrKindTimeout
		}
		return result.ErrKindDNS
	}

	if IsCertificateError(err) {
		return result.ErrKindCertificate
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return result.ErrKindTLS
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return result.ErrKindRefused
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return result.ErrKindReset
	}

	// Fall back to message matching for platform errors we do not name directly.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return result.ErrKindRefused
	case strings.Contains(msg, "reset by peer"):
		return result.ErrKindReset
	case strings.Contains(msg, "unreachable"):
		return result.ErrKindUnreachable
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "timed out"), strings.Contains(msg, "deadline exceeded"):
		return result.ErrKindTimeout
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "server misbehaving"):
		return result.ErrKindDNS
	case strings.Contains(msg, "certificate"):
		return result.ErrKindCertificate
	case strings.Contains(msg, "tls"):
		return result.ErrKindTLS
	}
	return result.ErrKindOther
}

// IsCertificateError reports whether err came from chain or hostname validation
// rather than from the connection itself.
func IsCertificateError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) ||
		errors.As(err, &invalid)
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// statusForConnect maps an error onto a connection outcome, where a refused or
// reset connection means "closed" rather than "broken".
func statusForConnect(pe *result.ProbeError) result.Status {
	switch {
	case pe == nil:
		return result.StatusOK
	case pe.Kind == result.ErrKindTimeout:
		return result.StatusTimeout
	case pe.Kind == result.ErrKindRefused, pe.Kind == result.ErrKindReset:
		return result.StatusClosed
	default:
		return result.StatusError
	}
}

// statusForProbe maps an error onto a diagnostic outcome.
func statusForProbe(pe *result.ProbeError) result.Status {
	switch {
	case pe == nil:
		return result.StatusOK
	case pe.Kind == result.ErrKindTimeout:
		return result.StatusTimeout
	default:
		return result.StatusError
	}
}
