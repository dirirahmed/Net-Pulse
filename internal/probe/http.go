package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// DefaultUserAgent identifies the tool to the servers it probes.
const DefaultUserAgent = "net-pulse/2.0"

const defaultMaxBodyBytes = 64 << 10

// HTTPOptions configures a request.
type HTTPOptions struct {
	Method          string
	Timeout         time.Duration
	FollowRedirects bool
	MaxRedirects    int
	UserAgent       string
	Headers         map[string]string
	RootCAs         *x509.CertPool
	Dialer          *net.Dialer
	MaxBodyBytes    int64
}

// HTTP issues one request and records status, timing and redirect information.
// A 4xx or 5xx response is still a successful probe: the failure is in
// StatusCode, not in Status.
func HTTP(ctx context.Context, rawURL string, opts HTTPOptions) result.HTTPResult {
	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodGet
	}
	res := result.HTTPResult{URL: rawURL, Method: method}

	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	var (
		mu    sync.Mutex
		ttfb  time.Duration
		start = time.Now()
	)
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			mu.Lock()
			if ttfb == 0 {
				ttfb = time.Since(start)
			}
			mu.Unlock()
		},
	}

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, rawURL, nil)
	if err != nil {
		res.Status = result.StatusError
		res.Error = &result.ProbeError{Kind: result.ErrKindHTTP, Message: err.Error()}
		return res
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialContextFunc(opts.Dialer, opts.Timeout),
		TLSClientConfig:       &tls.Config{RootCAs: opts.RootCAs},
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	defer transport.CloseIdleConnections()

	// CheckRedirect runs on the calling goroutine, so this slice needs no lock.
	var redirects []result.Redirect
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if !opts.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			hop := result.Redirect{To: r.URL.String()}
			if r.Response != nil {
				hop.StatusCode = r.Response.StatusCode
				hop.Location = r.Response.Header.Get("Location")
				if r.Response.Request != nil {
					hop.From = r.Response.Request.URL.String()
				}
			}
			redirects = append(redirects, hop)
			return nil
		},
	}

	resp, err := client.Do(req)

	mu.Lock()
	res.TTFB = result.Duration(ttfb)
	mu.Unlock()
	res.Redirects = redirects

	if err != nil {
		res.Duration = result.Since(start)
		res.Error = Classify(err)
		res.Status = statusForProbe(res.Error)
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.StatusText = resp.Status
	res.Proto = resp.Proto
	res.ContentLength = resp.ContentLength
	res.Headers = interestingHeaders(resp.Header)
	if resp.Request != nil && resp.Request.URL != nil {
		res.FinalURL = resp.Request.URL.String()
	}

	n, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	res.BodyBytes = n
	res.BodyTruncated = n == maxBody
	res.Duration = result.Since(start)

	if copyErr != nil {
		res.Error = Classify(copyErr)
		res.Status = statusForProbe(res.Error)
		return res
	}
	res.Status = result.StatusOK
	return res
}

func dialContextFunc(base *net.Dialer, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		if base != nil {
			d = *base
		}
		if timeout > 0 {
			d.Timeout = timeout
		}
		return d.DialContext(ctx, network, address)
	}
}

var reportedHeaders = []string{
	"Server",
	"Content-Type",
	"Content-Length",
	"Content-Encoding",
	"Location",
	"Cache-Control",
	"Strict-Transport-Security",
	"X-Powered-By",
	"Date",
}

func interestingHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string)
	for _, name := range reportedHeaders {
		if v := h.Get(name); v != "" {
			out[name] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
