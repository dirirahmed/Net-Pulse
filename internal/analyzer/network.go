package analyzer

import (
	"fmt"
	"strings"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/models"
)

// Network findings turn the scheduled target checks into the same explained
// findings as the PC checks. Like those, they quote measured values only.
// Evidence uses each target's name and a coarse reason, never addresses or
// raw error text, so a report can be summarised or sent on safely.

// NetTarget is one monitored target as the analysis sees it.
type NetTarget struct {
	Name                string
	Status              models.NetStatus
	Reason              string // models.NetReason* of the last check
	ConsecutiveFailures int
	ResponseMs          *float64
	HTTPStatus          *int
	CertDaysLeft        *int
	Uptime24h           *float64
	Checks24h           int
}

const (
	// minUptimeChecks avoids judging uptime from a handful of checks.
	minUptimeChecks = 10
	uptimeInfoBelow = 99.0
)

func reasonText(reason string, httpStatus *int) string {
	switch reason {
	case models.NetReasonDNS:
		return "its name did not resolve"
	case models.NetReasonConnect:
		return "the connection was refused or timed out"
	case models.NetReasonTLSHandshake:
		return "the TLS handshake failed"
	case models.NetReasonCertificate:
		return "its TLS certificate does not validate"
	case models.NetReasonHTTP:
		return "the HTTP request failed"
	case models.NetReasonServerError:
		if httpStatus != nil {
			return fmt.Sprintf("the server answered HTTP %d", *httpStatus)
		}
		return "the server answered with an error"
	case models.NetReasonSlow:
		return "it responded slowly"
	}
	return "the check failed"
}

func checks(n int) string {
	if n == 1 {
		return "check"
	}
	return fmt.Sprintf("%d checks", n)
}

// networkFindings evaluates every monitored target. Notes explain targets
// that were skipped.
func networkFindings(targets []NetTarget, n config.Network) ([]Finding, []string) {
	var out []Finding
	var notes []string
	var checked, down, blocked int
	dnsDown := 0
	for _, t := range targets {
		switch t.Status {
		case models.NetBlocked:
			blocked++
		case models.NetPending:
		default:
			checked++
			if t.Status == models.NetDown {
				down++
				if t.Reason == models.NetReasonDNS {
					dnsDown++
				}
			}
		}
	}
	if blocked > 0 {
		notes = append(notes, fmt.Sprintf("%d monitored target(s) point at private or local addresses and are blocked by the \"Allow private targets\" setting, so they were not checked.", blocked))
	}

	// Everything failing at once points at this PC's connection, not at
	// every service being down together.
	allDown := checked >= 2 && down == checked
	if allDown {
		f := Finding{
			ID: "net_all_down", Rule: "net_all_down", Category: "network", Severity: models.SeverityCritical,
			Title:    "All monitored network targets are unreachable",
			Evidence: fmt.Sprintf("All %d monitored targets failed their last check.", checked),
			Explanation: "When every target fails at the same time, the cause is usually this PC's own connection (Wi-Fi or cable, the router, " +
				"DNS or a VPN) rather than all of those services being down together.",
			Value: float64(down), Threshold: float64(checked), Unit: "targets",
			Recommendation: "Check this PC's network connection first: Wi-Fi or cable, then the router, then DNS or VPN settings.",
		}
		if dnsDown == checked {
			f.Evidence = fmt.Sprintf("All %d monitored targets failed their last check because their names did not resolve.", checked)
			f.Explanation = "Every name failing to resolve at once points at DNS: this PC's DNS server, the router, or no connection at all."
			f.Recommendation = "Check the internet connection, then this PC's or the router's DNS settings."
		}
		out = append(out, f)
	}

	for _, t := range targets {
		if t.Status == models.NetBlocked || t.Status == models.NetPending {
			continue
		}
		if t.Status == models.NetDown && !allDown {
			sev := models.SeverityWarning
			if t.ConsecutiveFailures >= n.FailuresBeforeAlert {
				sev = models.SeverityCritical
			}
			explanation := "Net-Pulse could not reach this target."
			if down < checked {
				explanation += " Other monitored targets are reachable, so this PC's connection is working and the problem is with this service or the route to it."
			}
			out = append(out, Finding{
				ID: "net_down:" + t.Name, Rule: "net_down", Category: "network", Target: t.Name, Severity: sev,
				Title:       t.Name + " is unreachable",
				Evidence:    fmt.Sprintf("%s failed its last %s: %s.", t.Name, checks(t.ConsecutiveFailures), reasonText(t.Reason, t.HTTPStatus)),
				Explanation: explanation,
				Value:       float64(t.ConsecutiveFailures), Threshold: float64(n.FailuresBeforeAlert), Unit: "checks",
				Recommendation: fmt.Sprintf("Check whether %s is up from another device or network, and whether its address is still correct.", t.Name),
			})
		}
		if t.Status == models.NetDegraded {
			if f := degradedFinding(t, n); f != nil {
				out = append(out, *f)
			}
		}
		if f := certFinding(t, n); f != nil {
			out = append(out, *f)
		}
		if t.Uptime24h != nil && t.Checks24h >= minUptimeChecks && *t.Uptime24h < uptimeInfoBelow && t.Status != models.NetDown {
			out = append(out, Finding{
				ID: "net_uptime:" + t.Name, Rule: "net_uptime", Category: "network", Target: t.Name, Severity: models.SeverityInfo,
				Title:       t.Name + " had outages in the last 24 hours",
				Evidence:    fmt.Sprintf("%s was reachable on %.1f%% of %d checks in the last 24 hours.", t.Name, *t.Uptime24h, t.Checks24h),
				Explanation: "It is reachable now, but some recent checks failed. Short, repeated outages often come from an unstable connection or an overloaded server.",
				Value:       *t.Uptime24h, Threshold: uptimeInfoBelow, Unit: "%",
				Recommendation: fmt.Sprintf("Open %s on the Network page to see when the failed checks happened.", t.Name),
			})
		}
	}
	return out, notes
}

func degradedFinding(t NetTarget, n config.Network) *Finding {
	f := Finding{ID: "net_degraded:" + t.Name, Category: "network", Target: t.Name, Severity: models.SeverityWarning}
	switch t.Reason {
	case models.NetReasonSlow:
		if t.ResponseMs == nil {
			return nil
		}
		f.Rule, f.Title = "net_slow", t.Name+" is responding slowly"
		f.Evidence = fmt.Sprintf("The last response from %s took %.0f ms; the limit is %d ms.", t.Name, *t.ResponseMs, n.SlowResponseMs)
		f.Explanation = "The service answers, but slowly. That is usually the server or the route to it; a slow PC does not slow down a network response."
		f.Value, f.Threshold, f.Unit = *t.ResponseMs, float64(n.SlowResponseMs), "ms"
		f.Recommendation = fmt.Sprintf("If %s is yours, check its server load; otherwise compare with another network to rule out your connection.", t.Name)
	case models.NetReasonServerError:
		f.Rule, f.Title = "net_server_error", t.Name+" is returning server errors"
		f.Evidence = fmt.Sprintf("%s is reachable, but %s.", t.Name, reasonText(t.Reason, t.HTTPStatus))
		f.Explanation = "A 5xx status means the server received the request but failed to handle it. The network path is working."
		if t.HTTPStatus != nil {
			f.Value = float64(*t.HTTPStatus)
		}
		f.Threshold, f.Unit = 500, "HTTP status"
		f.Recommendation = fmt.Sprintf("Check the service behind %s; the problem is on the server, not this PC.", t.Name)
	case models.NetReasonCertificate:
		f.Rule, f.Title = "net_cert_invalid", t.Name+" has a TLS certificate problem"
		f.Evidence = fmt.Sprintf("%s is reachable, but %s.", t.Name, reasonText(t.Reason, nil))
		f.Explanation = "Browsers will show a security warning. Common causes are an expired certificate, a name mismatch or a missing intermediate certificate."
		f.Unit = "certificate"
		f.Recommendation = fmt.Sprintf("Renew or fix the certificate for %s; run a scan on the Network page to see its details.", t.Name)
	default:
		return nil
	}
	return &f
}

func certFinding(t NetTarget, n config.Network) *Finding {
	if t.CertDaysLeft == nil {
		return nil
	}
	days := *t.CertDaysLeft
	sev := models.Severity("")
	switch {
	case days <= n.CertExpiry.CriticalDays:
		sev = models.SeverityCritical
	case days <= n.CertExpiry.WarningDays:
		sev = models.SeverityWarning
	default:
		return nil
	}
	f := Finding{
		ID: "net_cert:" + t.Name, Rule: "net_cert_expiry", Category: "network", Target: t.Name, Severity: sev,
		Value: float64(days), Threshold: float64(n.CertExpiry.WarningDays), Unit: "days",
		Recommendation: fmt.Sprintf("Renew the TLS certificate for %s.", t.Name),
	}
	if days < 0 {
		f.Title = "The TLS certificate for " + t.Name + " has expired"
		f.Evidence = fmt.Sprintf("The certificate for %s expired %d days ago.", t.Name, -days)
		f.Explanation = "Browsers and API clients refuse an expired certificate, so visitors see an error page."
	} else {
		f.Title = "The TLS certificate for " + t.Name + " expires soon"
		f.Evidence = fmt.Sprintf("The certificate for %s expires in %d days.", t.Name, days)
		f.Explanation = "Once it expires, browsers and API clients will refuse the connection. Automated renewal (for example with Let's Encrypt) can fail silently."
	}
	return &f
}

// onlyNetwork reports whether every finding is about the network.
func onlyNetwork(findings []Finding) bool {
	for _, f := range findings {
		if f.Category != "network" {
			return false
		}
	}
	return len(findings) > 0
}

// networkTargetsNote is used when monitoring is available but empty.
const networkTargetsNote = "No network targets are monitored, so connectivity is not part of this analysis. Add websites or services on the Network page to include it."

func joinSentence(parts ...string) string { return strings.Join(parts, " ") }
