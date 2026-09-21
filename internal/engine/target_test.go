package engine

import "testing"

func TestParseTargetValid(t *testing.T) {
	cases := []struct {
		raw    string
		host   string
		port   int
		scheme string
		isIP   bool
	}{
		{"example.com", "example.com", 0, "", false},
		{"example.com:8443", "example.com", 8443, "", false},
		{"8.8.8.8", "8.8.8.8", 0, "", true},
		{"1.1.1.1:53", "1.1.1.1", 53, "", true},
		{"[::1]:443", "::1", 443, "", true},
		{"::1", "::1", 0, "", true},
		{"https://example.com/health", "example.com", 0, "https", false},
		{"http://example.com:8080/", "example.com", 8080, "http", false},
		{"  example.com  ", "example.com", 0, "", false},
	}

	for _, c := range cases {
		got, err := ParseTarget(c.raw)
		if err != nil {
			t.Errorf("ParseTarget(%q) failed: %v", c.raw, err)
			continue
		}
		if got.Host != c.host || got.Port != c.port || got.Scheme != c.scheme || got.IsIP != c.isIP {
			t.Errorf("ParseTarget(%q) = %+v, want host=%s port=%d scheme=%s isIP=%t",
				c.raw, got, c.host, c.port, c.scheme, c.isIP)
		}
	}
}

func TestParseTargetInvalid(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"ftp://example.com",
		"example.com:0",
		"example.com:99999",
		"example.com:abc",
		"exa mple.com",
		"http://",
		"exam/ple.com",
	}

	for _, raw := range cases {
		if got, err := ParseTarget(raw); err == nil {
			t.Errorf("ParseTarget(%q) succeeded with %+v, want an error", raw, got)
		}
	}
}

func TestBuildURL(t *testing.T) {
	tgt, err := ParseTarget("https://example.com/health")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got := buildURL(tgt, 443, true); got != "https://example.com/health" {
		t.Errorf("buildURL = %q", got)
	}

	tgt, err = ParseTarget("example.com:8080")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got := buildURL(tgt, 8080, false); got != "http://example.com:8080/" {
		t.Errorf("buildURL = %q", got)
	}
}
