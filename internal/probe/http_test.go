package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/result"
)

func TestHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "net-pulse-test")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pulse"))
	}))
	defer srv.Close()

	res := HTTP(context.Background(), srv.URL, HTTPOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: true,
	})

	if res.Status != result.StatusOK {
		t.Fatalf("status = %q (%v)", res.Status, res.Error)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", res.StatusCode)
	}
	if res.BodyBytes != int64(len("pulse")) {
		t.Errorf("body bytes = %d, want %d", res.BodyBytes, len("pulse"))
	}
	if res.Headers["Server"] != "net-pulse-test" {
		t.Errorf("Server header = %q", res.Headers["Server"])
	}
	if res.Duration < 0 {
		t.Errorf("duration = %s, must not be negative", res.Duration)
	}
}

func TestHTTPServerErrorIsStillASuccessfulProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	res := HTTP(context.Background(), srv.URL, HTTPOptions{Timeout: 5 * time.Second})
	if res.Status != result.StatusOK {
		t.Fatalf("status = %q, want ok: the request itself worked", res.Status)
	}
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("status code = %d, want 500", res.StatusCode)
	}
}

func TestHTTPRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := HTTP(context.Background(), srv.URL+"/", HTTPOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: true,
	})

	if res.Status != result.StatusOK {
		t.Fatalf("status = %q (%v)", res.Status, res.Error)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want 200", res.StatusCode)
	}
	if len(res.Redirects) != 1 {
		t.Fatalf("recorded %d redirects, want 1", len(res.Redirects))
	}
	if res.Redirects[0].StatusCode != http.StatusFound {
		t.Errorf("redirect status = %d, want 302", res.Redirects[0].StatusCode)
	}
	if !strings.HasSuffix(res.FinalURL, "/final") {
		t.Errorf("final url = %q, want it to end in /final", res.FinalURL)
	}
}

func TestHTTPRedirectsNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	res := HTTP(context.Background(), srv.URL+"/", HTTPOptions{
		Timeout:         5 * time.Second,
		FollowRedirects: false,
	})

	if res.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status code = %d, want 301", res.StatusCode)
	}
	if len(res.Redirects) != 0 {
		t.Errorf("recorded %d redirects, want 0", len(res.Redirects))
	}
	if res.Headers["Location"] == "" {
		t.Error("expected the Location header to be captured")
	}
}

func TestHTTPTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	res := HTTP(context.Background(), srv.URL, HTTPOptions{Timeout: 100 * time.Millisecond})

	if res.Status != result.StatusTimeout {
		t.Fatalf("status = %q (%v), want timeout", res.Status, res.Error)
	}
	if res.Error == nil || res.Error.Kind != result.ErrKindTimeout {
		t.Fatalf("error = %v, want a timeout kind", res.Error)
	}
}

func TestHTTPConnectionRefused(t *testing.T) {
	res := HTTP(context.Background(), "http://"+closedAddress(t)+"/", HTTPOptions{Timeout: 2 * time.Second})

	if res.Status != result.StatusError {
		t.Fatalf("status = %q, want error", res.Status)
	}
	if res.Error == nil || res.Error.Kind != result.ErrKindRefused {
		t.Fatalf("error = %v, want a refused kind", res.Error)
	}
}

func TestHTTPMalformedURL(t *testing.T) {
	res := HTTP(context.Background(), "http://%zz/", HTTPOptions{Timeout: time.Second})
	if res.Status != result.StatusError {
		t.Fatalf("status = %q, want error", res.Status)
	}
	if res.Error == nil {
		t.Fatal("expected a structured error")
	}
}

func TestHTTPBodyTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	res := HTTP(context.Background(), srv.URL, HTTPOptions{
		Timeout:      5 * time.Second,
		MaxBodyBytes: 512,
	})

	if res.BodyBytes != 512 {
		t.Fatalf("body bytes = %d, want 512", res.BodyBytes)
	}
	if !res.BodyTruncated {
		t.Error("expected BodyTruncated to be true")
	}
}
