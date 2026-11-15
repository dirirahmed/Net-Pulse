package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dirirahmed/Net-Pulse/internal/config"
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

func TestDemoConfigIsValidAndSafe(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "deploy", "demo-config.json"))
	if err != nil {
		t.Fatalf("deploy/demo-config.json: %v", err)
	}
	if len(cfg.Network.Targets) == 0 {
		t.Fatal("the demo should come with targets to show")
	}
	cfg.Network.AllowPrivateTargets = true // as if someone edited the file
	applyDemo(&cfg)
	if cfg.Network.AllowPrivateTargets || cfg.ListenAddress != "0.0.0.0" {
		t.Errorf("applyDemo left %+v / %q", cfg.Network.AllowPrivateTargets, cfg.ListenAddress)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("demo config invalid after applyDemo: %v", err)
	}
}

func TestDemoPort(t *testing.T) {
	t.Setenv("PORT", "10000")
	if got := demoPort(0); got != 10000 {
		t.Errorf("from $PORT: %d", got)
	}
	if got := demoPort(8080); got != 8080 {
		t.Errorf("an explicit -port must win: %d", got)
	}
	t.Setenv("PORT", "not-a-port")
	if got := demoPort(0); got != 0 {
		t.Errorf("invalid $PORT: %d", got)
	}
}
