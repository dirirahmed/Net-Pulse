package engine

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// ParseTarget accepts "example.com", "example.com:8443", "1.1.1.1",
// "[::1]:443" and full "https://example.com/path" URLs.
func ParseTarget(raw string) (result.Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return result.Target{}, errors.New("empty target")
	}

	t := result.Target{Raw: s}

	switch {
	case strings.Contains(s, "://"):
		u, err := url.Parse(s)
		if err != nil {
			return result.Target{}, fmt.Errorf("invalid target %q: %w", raw, err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return result.Target{}, fmt.Errorf("unsupported scheme %q: only http and https are supported", u.Scheme)
		}
		if u.Hostname() == "" {
			return result.Target{}, fmt.Errorf("invalid target %q: missing host", raw)
		}
		t.Scheme = scheme
		t.Host = u.Hostname()
		t.Path = u.Path
		if p := u.Port(); p != "" {
			port, err := parsePort(p)
			if err != nil {
				return result.Target{}, fmt.Errorf("invalid target %q: %w", raw, err)
			}
			t.Port = port
		}

	default:
		if host, port, err := net.SplitHostPort(s); err == nil {
			n, perr := parsePort(port)
			if perr != nil {
				return result.Target{}, fmt.Errorf("invalid target %q: %w", raw, perr)
			}
			t.Host = strings.Trim(host, "[]")
			t.Port = n
		} else {
			t.Host = strings.Trim(s, "[]")
		}
	}

	if t.Host == "" {
		return result.Target{}, fmt.Errorf("invalid target %q: missing host", raw)
	}
	if strings.ContainsAny(t.Host, " \t/\\?#@") {
		return result.Target{}, fmt.Errorf("invalid host %q", t.Host)
	}
	t.IsIP = net.ParseIP(t.Host) != nil
	if !t.IsIP && !validHostname(t.Host) {
		return result.Target{}, fmt.Errorf("invalid host %q", t.Host)
	}
	return t, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", n)
	}
	return n, nil
}

func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z',
				c >= 'A' && c <= 'Z',
				c >= '0' && c <= '9',
				c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
