package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultsAreValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}

func TestLoadPartialFileMergesOntoDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"port": 9000, "thresholds": {"cpuUsage": {"warning": 80, "critical": 90, "sustainSeconds": 30}}}`), 0o644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 9000 || cfg.Thresholds.CPUUsage.Warning != 80 {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.RetentionDays != Default().RetentionDays || cfg.Thresholds.MemoryUsage != Default().Thresholds.MemoryUsage {
		t.Error("unspecified fields should keep defaults")
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"retentionDays": 0}`), 0o644)
	cfg, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "retentionDays") {
		t.Fatalf("expected retentionDays error, got %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Error("invalid file should fall back to defaults")
	}
}

func TestValidateThresholdOrdering(t *testing.T) {
	c := Default()
	c.Thresholds.CPUUsage.Critical = c.Thresholds.CPUUsage.Warning - 1
	c.Thresholds.DiskFreePercent.Critical = c.Thresholds.DiskFreePercent.Warning + 1
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "cpuUsage.critical") || !strings.Contains(err.Error(), "diskFreePercent.critical") {
		t.Fatalf("expected both ordering errors, got %v", err)
	}
}

func TestStoreUpdatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.json")
	s := NewStore(path, Default())
	next := Default()
	next.SampleIntervalSeconds = 5
	if err := s.Update(next); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.SampleIntervalSeconds != 5 {
		t.Fatalf("persisted config = %+v, err %v", loaded, err)
	}
	bad := next
	bad.Port = 0
	if err := s.Update(bad); err == nil {
		t.Fatal("invalid update accepted")
	}
	if s.Get().Port != Default().Port {
		t.Error("rejected update must not change live config")
	}
}

// The documented example must stay loadable and in sync with the defaults.
func TestExampleConfigMatchesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Errorf("config.example.json differs from Default():\n%+v\n%+v", cfg, Default())
	}
}

func validNetwork() Config {
	c := Default()
	c.Network.Targets = []NetTarget{
		{ID: "site", Name: "My site", Target: "https://example.com/health"},
		{ID: "dns-1", Name: "Cloudflare DNS", Target: "1.1.1.1:53"},
	}
	return c
}

func TestNetworkTargetsValidate(t *testing.T) {
	if err := validNetwork().Validate(); err != nil {
		t.Fatalf("valid targets rejected: %v", err)
	}
	cases := map[string]func(*Config){
		"id must be":           func(c *Config) { c.Network.Targets[0].ID = "Bad ID" },
		"used more than once":  func(c *Config) { c.Network.Targets[1].ID = "site" },
		"name must be":         func(c *Config) { c.Network.Targets[0].Name = "  " },
		"targets[1].target":    func(c *Config) { c.Network.Targets[1].Target = "ftp://example.com" },
		"checkIntervalSeconds": func(c *Config) { c.Network.CheckIntervalSeconds = 5 },
		"warningDays":          func(c *Config) { c.Network.CertExpiry.WarningDays = 3 },
		"at most":              func(c *Config) { c.Network.Targets = make([]NetTarget, MaxTargets+1) },
	}
	for want, mutate := range cases {
		c := validNetwork()
		mutate(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}

func TestStoreGetReturnsIndependentCopy(t *testing.T) {
	s := NewStore("", validNetwork())
	got := s.Get()
	got.Network.Targets[0].Name = "changed"
	got.Network.Targets = append(got.Network.Targets[:0], NetTarget{ID: "x", Name: "x", Target: "x.io"})
	if s.Get().Network.Targets[0].Name != "My site" {
		t.Fatal("modifying a Get() result changed the stored config")
	}
}

func TestLoadNullTargetsMeansNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"network": {"targets": null}}`), 0o644)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.Targets == nil || len(cfg.Network.Targets) != 0 {
		t.Fatalf("targets = %#v, want empty slice", cfg.Network.Targets)
	}
}
