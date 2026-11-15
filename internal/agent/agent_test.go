package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPickDataDirPrefersNewName(t *testing.T) {
	base := t.TempDir()
	if got, want := pickDataDir(base), filepath.Join(base, dataDirName); got != want {
		t.Fatalf("fresh install: got %s, want %s", got, want)
	}
}

func TestPickDataDirReusesLegacyInstall(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, legacyDataDirName)
	if err := os.Mkdir(legacy, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := pickDataDir(base); got != legacy {
		t.Fatalf("legacy only: got %s, want %s", got, legacy)
	}
	// Once a NetPulse directory exists it wins, even if the legacy one remains.
	current := filepath.Join(base, dataDirName)
	if err := os.Mkdir(current, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := pickDataDir(base); got != current {
		t.Fatalf("both present: got %s, want %s", got, current)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"extra"}, &stderr)
	if err == nil || !strings.Contains(err.Error(), "no arguments") {
		t.Fatalf("want an argument error, got %v", err)
	}
}

func TestRunHelp(t *testing.T) {
	var stderr bytes.Buffer
	if err := Run(context.Background(), []string{"-h"}, &stderr); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stderr.String(), "netpulse serve") {
		t.Fatalf("usage missing command name:\n%s", stderr.String())
	}
}
