package models

import "time"

// NetStatus is the outcome of one scheduled check of a monitored target.
type NetStatus string

const (
	// NetPending: configured but not checked yet.
	NetPending NetStatus = "pending"
	// NetUp: name resolved, the port connected, TLS verified (when used) and
	// the web server answered (when HTTP applies) without a 5xx.
	NetUp NetStatus = "up"
	// NetDegraded: reachable, but slow, a 5xx response, or a certificate
	// that doesn't validate.
	NetDegraded NetStatus = "degraded"
	// NetDown: DNS, the TCP connection, the TLS handshake or the HTTP
	// request failed.
	NetDown NetStatus = "down"
	// NetBlocked: refused by the target guard (private/reserved address
	// while private targets are not allowed). A setting, not an outage.
	NetBlocked NetStatus = "blocked"
)

// NetCheck is one scheduled check. Timing fields are nil when that step
// didn't run (for example TLS on a plain-HTTP target, or anything after a
// DNS failure).
type NetCheck struct {
	TargetID   string    `json:"targetId"`
	Timestamp  time.Time `json:"timestamp"`
	Status     NetStatus `json:"status"`
	DNSMs      *float64  `json:"dnsMs"`
	ConnectMs  *float64  `json:"connectMs"`
	TLSMs      *float64  `json:"tlsMs"`
	TTFBMs     *float64  `json:"ttfbMs"`
	ResponseMs *float64  `json:"responseMs"`
	HTTPStatus *int      `json:"httpStatus"`
	// CertDaysLeft is the leaf certificate's remaining validity.
	CertDaysLeft *int `json:"certDaysLeft"`
	// Problem is a one-line reason when Status is not up.
	Problem string `json:"problem,omitempty"`
	// Reason is a coarse code for Problem (see the NetReason constants).
	// It carries no addresses or error text, so it is safe to summarise or
	// send on where the raw Problem is not.
	Reason string `json:"reason,omitempty"`
}

// Reason codes for NetCheck.Reason.
const (
	NetReasonDNS          = "dns"
	NetReasonConnect      = "connect"
	NetReasonTLSHandshake = "tls_handshake"
	NetReasonCertificate  = "certificate"
	NetReasonHTTP         = "http"
	NetReasonServerError  = "server_error"
	NetReasonSlow         = "slow"
	NetReasonBlocked      = "blocked"
)

// NetCheckPoint is a bucket of checks for long-range charts.
type NetCheckPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	Checks        int       `json:"checks"`
	Up            int       `json:"up"`
	Degraded      int       `json:"degraded"`
	Down          int       `json:"down"`
	AvgResponseMs *float64  `json:"avgResponseMs"`
	MaxResponseMs *float64  `json:"maxResponseMs"`
}

// NetUptime counts checks over a period. Blocked and pending checks are not
// counted: they say nothing about whether the target works.
type NetUptime struct {
	Checks   int `json:"checks"`
	Up       int `json:"up"`
	Degraded int `json:"degraded"`
	Down     int `json:"down"`
}

// Percent is the share of checks that reached the target (up or degraded),
// or nil when there were no checks.
func (u NetUptime) Percent() *float64 {
	if u.Checks == 0 {
		return nil
	}
	p := float64(u.Up+u.Degraded) / float64(u.Checks) * 100
	return &p
}
