// Package result holds the structured types produced by the Net-Pulse engine.
// These types are pure data: they never format output and never touch the
// network, so the CLI today and a backend/API later can consume the same values.
package result

import (
	"strconv"
	"time"
)

// Status is the outcome of a single probe.
type Status string

const (
	StatusOK      Status = "ok"
	StatusOpen    Status = "open"
	StatusClosed  Status = "closed"
	StatusTimeout Status = "timeout"
	StatusError   Status = "error"
	StatusSkipped Status = "skipped"
)

// ErrorKind is a coarse classification of a failure, stable enough to group on
// later when results are stored historically.
type ErrorKind string

const (
	ErrKindTimeout     ErrorKind = "timeout"
	ErrKindCanceled    ErrorKind = "canceled"
	ErrKindDNS         ErrorKind = "dns"
	ErrKindRefused     ErrorKind = "refused"
	ErrKindReset       ErrorKind = "reset"
	ErrKindUnreachable ErrorKind = "unreachable"
	ErrKindTLS         ErrorKind = "tls"
	ErrKindCertificate ErrorKind = "certificate"
	ErrKindHTTP        ErrorKind = "http"
	ErrKindOther       ErrorKind = "other"
)

// ProbeError is a serialisable error.
type ProbeError struct {
	Kind    ErrorKind `json:"kind"`
	Message string    `json:"message"`
}

func (e *ProbeError) String() string {
	if e == nil {
		return ""
	}
	return string(e.Kind) + ": " + e.Message
}

// Duration is a time.Duration that marshals as milliseconds, which keeps stored
// results readable and easy to chart later.
type Duration time.Duration

// Since is shorthand for the common "measure from start" pattern.
func Since(start time.Time) Duration { return Duration(time.Since(start)) }

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) Millis() float64 { return float64(d) / float64(time.Millisecond) }

func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatFloat(d.Millis(), 'f', 3, 64)), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
	}
	*d = Duration(f * float64(time.Millisecond))
	return nil
}

// Target is a parsed scan target.
type Target struct {
	Raw    string `json:"raw"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Path   string `json:"path,omitempty"`
	IsIP   bool   `json:"is_ip"`
}

// Report is the top-level result of one scan of one target.
type Report struct {
	Target    Target    `json:"target"`
	StartedAt time.Time `json:"started_at"`
	Duration  Duration  `json:"duration_ms"`

	DNS   *DNSResult      `json:"dns,omitempty"`
	Ports *PortScanResult `json:"ports,omitempty"`
	TCP   *TCPResult      `json:"tcp,omitempty"`
	TLS   *TLSResult      `json:"tls,omitempty"`
	HTTP  *HTTPResult     `json:"http,omitempty"`

	// Notes records engine-level decisions such as skipped checks.
	Notes []string `json:"notes,omitempty"`
}

// DNSResult records a forward lookup.
type DNSResult struct {
	Host      string      `json:"host"`
	Status    Status      `json:"status"`
	Addresses []string    `json:"addresses,omitempty"`
	Primary   string      `json:"primary,omitempty"`
	CNAME     string      `json:"cname,omitempty"`
	Literal   bool        `json:"literal,omitempty"`
	Duration  Duration    `json:"duration_ms"`
	Error     *ProbeError `json:"error,omitempty"`
}

// PortResult is one port of a scan.
type PortResult struct {
	Port     int         `json:"port"`
	Service  string      `json:"service,omitempty"`
	Status   Status      `json:"status"`
	Duration Duration    `json:"duration_ms"`
	Error    *ProbeError `json:"error,omitempty"`
}

func (p PortResult) IsOpen() bool { return p.Status == StatusOpen }

// PortScanResult groups the ports probed for one target.
type PortScanResult struct {
	Host     string       `json:"host"`
	Address  string       `json:"address,omitempty"`
	Scanned  int          `json:"scanned"`
	Open     int          `json:"open"`
	Duration Duration     `json:"duration_ms"`
	Results  []PortResult `json:"results,omitempty"`
}

// OpenPorts returns only the ports that completed a handshake.
func (p *PortScanResult) OpenPorts() []PortResult {
	if p == nil {
		return nil
	}
	var open []PortResult
	for _, r := range p.Results {
		if r.IsOpen() {
			open = append(open, r)
		}
	}
	return open
}

// TCPResult records a single connection attempt.
type TCPResult struct {
	Address    string      `json:"address"`
	Status     Status      `json:"status"`
	Duration   Duration    `json:"duration_ms"`
	LocalAddr  string      `json:"local_addr,omitempty"`
	RemoteAddr string      `json:"remote_addr,omitempty"`
	Timeout    Duration    `json:"timeout_ms"`
	Error      *ProbeError `json:"error,omitempty"`
}

// Certificate is the interesting subset of an x509 certificate.
type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	CommonName         string    `json:"common_name,omitempty"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	SerialNumber       string    `json:"serial_number,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysUntilExpiry    int       `json:"days_until_expiry"`
	Expired            bool      `json:"expired"`
	NotYetValid        bool      `json:"not_yet_valid,omitempty"`
	SelfSigned         bool      `json:"self_signed,omitempty"`
	IsCA               bool      `json:"is_ca,omitempty"`
}

// TLSResult records a real TLS handshake.
type TLSResult struct {
	Address           string   `json:"address"`
	ServerName        string   `json:"server_name,omitempty"`
	Status            Status   `json:"status"`
	DialDuration      Duration `json:"dial_duration_ms"`
	HandshakeDuration Duration `json:"handshake_duration_ms"`

	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	ALPN        string `json:"alpn,omitempty"`

	// Verified is true only when the chain validated against the trust store.
	Verified bool `json:"verified"`

	Certificates []Certificate `json:"certificates,omitempty"`

	// Leaf convenience fields, copied from Certificates[0].
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	DaysUntilExpiry int       `json:"days_until_expiry,omitempty"`
	Expired         bool      `json:"expired,omitempty"`

	VerifyError *ProbeError `json:"verify_error,omitempty"`
	Error       *ProbeError `json:"error,omitempty"`
}

// Redirect is one hop of a redirect chain.
type Redirect struct {
	From       string `json:"from,omitempty"`
	To         string `json:"to"`
	StatusCode int    `json:"status_code,omitempty"`
	Location   string `json:"location,omitempty"`
}

// HTTPResult records one HTTP or HTTPS request.
//
// Status describes the transport-level outcome: StatusOK means a response was
// received, even if StatusCode is 4xx or 5xx.
type HTTPResult struct {
	URL      string `json:"url"`
	Method   string `json:"method"`
	Status   Status `json:"status"`
	FinalURL string `json:"final_url,omitempty"`

	StatusCode int    `json:"status_code,omitempty"`
	StatusText string `json:"status_text,omitempty"`
	Proto      string `json:"proto,omitempty"`

	TTFB     Duration `json:"ttfb_ms"`
	Duration Duration `json:"duration_ms"`

	ContentLength int64             `json:"content_length,omitempty"`
	BodyBytes     int64             `json:"body_bytes,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Redirects     []Redirect        `json:"redirects,omitempty"`

	Error *ProbeError `json:"error,omitempty"`
}
