package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/probe"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

const rule = "------------------------------------------------------------"

// Render writes a readable summary of a report. It only reads the structured
// result: no networking happens here.
func Render(w io.Writer, rep result.Report, showClosed bool) {
	fmt.Fprintf(w, "Net-Pulse v2 diagnostics for: %s\n", rep.Target.Raw)
	fmt.Fprintln(w, rule)

	renderDNS(w, rep.DNS)
	renderTCP(w, rep.TCP)
	renderTLS(w, rep.TLS)
	renderHTTP(w, rep.HTTP)
	renderPorts(w, rep.Ports, showClosed)

	for _, note := range rep.Notes {
		fmt.Fprintf(w, "\nnote: %s\n", note)
	}

	fmt.Fprintln(w, rule)
	fmt.Fprintf(w, "Scan complete in %s\n", ms(rep.Duration))
}

func renderDNS(w io.Writer, d *result.DNSResult) {
	if d == nil {
		return
	}
	fmt.Fprintf(w, "\n[DNS]   %-8s %10s\n", d.Status, ms(d.Duration))
	if d.Literal {
		fmt.Fprintf(w, "        target is an IP literal, no lookup needed\n")
	}
	if len(d.Addresses) > 0 {
		fmt.Fprintf(w, "        addresses: %s\n", strings.Join(d.Addresses, ", "))
	}
	if d.CNAME != "" {
		fmt.Fprintf(w, "        cname:     %s\n", d.CNAME)
	}
	if d.Error != nil {
		fmt.Fprintf(w, "        error:     %s\n", d.Error.String())
	}
}

func renderTCP(w io.Writer, t *result.TCPResult) {
	if t == nil {
		return
	}
	fmt.Fprintf(w, "\n[TCP]   %-8s %10s  %s\n", t.Status, ms(t.Duration), t.Address)
	if t.Error != nil {
		fmt.Fprintf(w, "        error:     %s\n", t.Error.String())
	}
}

func renderTLS(w io.Writer, t *result.TLSResult) {
	if t == nil {
		return
	}
	fmt.Fprintf(w, "\n[TLS]   %-8s %10s  handshake\n", t.Status, ms(t.HandshakeDuration))
	if t.Version != "" {
		fmt.Fprintf(w, "        version:   %s  cipher: %s\n", t.Version, t.CipherSuite)
	}
	if t.ALPN != "" {
		fmt.Fprintf(w, "        alpn:      %s\n", t.ALPN)
	}
	fmt.Fprintf(w, "        verified:  %t\n", t.Verified)

	if len(t.Certificates) > 0 {
		leaf := t.Certificates[0]
		fmt.Fprintf(w, "        subject:   %s\n", leaf.Subject)
		fmt.Fprintf(w, "        issuer:    %s\n", leaf.Issuer)
		if len(leaf.DNSNames) > 0 {
			fmt.Fprintf(w, "        sans:      %s\n", strings.Join(leaf.DNSNames, ", "))
		}
		fmt.Fprintf(w, "        expires:   %s (%s)\n",
			leaf.NotAfter.Format(time.RFC3339), expiryPhrase(leaf))
	}
	if t.VerifyError != nil {
		fmt.Fprintf(w, "        verify:    %s\n", t.VerifyError.String())
	} else if t.Error != nil {
		fmt.Fprintf(w, "        error:     %s\n", t.Error.String())
	}
}

func expiryPhrase(c result.Certificate) string {
	switch {
	case c.Expired:
		return fmt.Sprintf("EXPIRED %d days ago", -c.DaysUntilExpiry)
	case c.NotYetValid:
		return "not yet valid"
	default:
		return fmt.Sprintf("in %d days", c.DaysUntilExpiry)
	}
}

func renderHTTP(w io.Writer, h *result.HTTPResult) {
	if h == nil {
		return
	}
	code := "-"
	if h.StatusCode != 0 {
		code = fmt.Sprintf("%d", h.StatusCode)
	}
	fmt.Fprintf(w, "\n[HTTP]  %-8s %10s  %s %s -> %s\n", h.Status, ms(h.Duration), h.Method, code, h.URL)
	if h.TTFB > 0 {
		fmt.Fprintf(w, "        ttfb:      %s\n", ms(h.TTFB))
	}
	if h.Proto != "" {
		fmt.Fprintf(w, "        proto:     %s\n", h.Proto)
	}
	if h.FinalURL != "" && h.FinalURL != h.URL {
		fmt.Fprintf(w, "        final url: %s\n", h.FinalURL)
	}
	for _, r := range h.Redirects {
		fmt.Fprintf(w, "        redirect:  %d %s -> %s\n", r.StatusCode, r.From, r.To)
	}
	for _, name := range []string{"Server", "Content-Type", "Strict-Transport-Security"} {
		if v, ok := h.Headers[name]; ok {
			fmt.Fprintf(w, "        %-10s %s\n", strings.ToLower(name)+":", v)
		}
	}
	if h.Error != nil {
		fmt.Fprintf(w, "        error:     %s\n", h.Error.String())
	}
}

func renderPorts(w io.Writer, p *result.PortScanResult, showClosed bool) {
	if p == nil {
		return
	}
	fmt.Fprintf(w, "\n[PORTS] %d/%d open %s (%s)\n", p.Open, p.Scanned, ms(p.Duration), p.Address)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range p.Results {
		if !r.IsOpen() && !showClosed {
			continue
		}
		label := r.Service
		if label == "" {
			label = "unknown"
		}
		fmt.Fprintf(tw, "        [%s]\t%d\t%s\t%s\t%s\n",
			strings.ToUpper(string(r.Status)), r.Port, label, ms(r.Duration), probe.ServiceDescription(r.Port))
	}
	tw.Flush()

	if p.Open == 0 && !showClosed {
		fmt.Fprintf(w, "        no open ports found (use -show-closed to see every result)\n")
	}
}

func ms(d result.Duration) string {
	return fmt.Sprintf("%.1fms", d.Millis())
}
