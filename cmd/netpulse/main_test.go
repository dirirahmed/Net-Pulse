package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpListsCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(context.Background(), []string{"help"}, &out, &errOut); err != nil {
		t.Fatalf("help: %v", err)
	}
	for _, want := range []string{"netpulse scan", "netpulse serve"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help output missing %q:\n%s", want, out.String())
		}
	}
}

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != "netpulse dev" {
		t.Errorf("version output = %q", got)
	}
}

func TestUnknownCommandIsRejected(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run(context.Background(), []string{"sevre"}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("want unknown command error, got %v", err)
	}
}

func TestLooksLikeTarget(t *testing.T) {
	for in, want := range map[string]bool{
		"example.com": true, "1.1.1.1": true, "[::1]:443": true, "https://x.io/": true,
		"localhost": true, "serve2": false, "sevre": false,
	} {
		if got := looksLikeTarget(in); got != want {
			t.Errorf("looksLikeTarget(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestScanFlagErrorsComeFromTheCLI(t *testing.T) {
	var out, errOut bytes.Buffer
	// An invalid port spec fails before any network access.
	err := run(context.Background(), []string{"scan", "-ports", "99999", "example.com"}, &out, &errOut)
	if err == nil {
		t.Fatal("want an error for an out-of-range port")
	}
}
