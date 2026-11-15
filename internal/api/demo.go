package api

import (
	"net/http"
	"sync"
	"time"
)

// Demo mode serves a public, read-only showcase: the dashboard monitors the
// server it runs on, configuration can't be changed, every target goes
// through the private-address guard, on-demand scans are rate-limited and
// smaller, and the AI assistant is off.

const (
	demoReadOnlyMsg = "This is the live demo, so settings and monitored targets are read-only. Run Net-Pulse on your own PC to change them."
	demoAIMsg       = "Ask Pulse is turned off in the live demo. Run Net-Pulse on your own PC with an API key to use it."
	// demoScansPerMinute is shared by every visitor; one scan also runs at a
	// time (netwatch), so this mostly bounds sustained use.
	demoScansPerMinute = 10
	demoMaxScanPorts   = 64
)

// WithDemo turns on demo mode. See the package comment above.
func (s *Server) WithDemo(on bool) *Server {
	s.demo = on
	if on {
		s.scanLimit = newRateLimiter(demoScansPerMinute, time.Minute)
	}
	return s
}

// readOnly writes 403 in demo mode and reports whether it did.
func (s *Server) readOnly(w http.ResponseWriter) bool {
	if !s.demo {
		return false
	}
	writeJSON(w, http.StatusForbidden, errorResponse{Error: demoReadOnlyMsg, Demo: true})
	return true
}

// rateLimiter is a token bucket: up to n events, refilled evenly over per.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64 // tokens per second
	last   time.Time
	now    func() time.Time
}

func newRateLimiter(n int, per time.Duration) *rateLimiter {
	return &rateLimiter{tokens: float64(n), max: float64(n), rate: float64(n) / per.Seconds(), now: time.Now}
}

// allow takes a token if one is available.
func (l *rateLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.last.IsZero() {
		l.tokens = min(l.max, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
