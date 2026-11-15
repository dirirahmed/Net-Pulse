package netwatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/result"
	"github.com/dirirahmed/Net-Pulse/internal/safety"
)

func scanService(t *testing.T, allowPrivate bool, run Runner) *Service {
	t.Helper()
	c := config.Default()
	c.Network.AllowPrivateTargets = allowPrivate
	return New(Options{Config: config.NewStore("", c), Logger: quiet, Runner: run})
}

func mustTarget(t *testing.T, raw string) result.Target {
	t.Helper()
	tg, err := engine.ParseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestScanAppliesGuardAndLimits(t *testing.T) {
	var got engine.Options
	svc := scanService(t, false, func(_ context.Context, _ result.Target, o engine.Options) result.Report {
		got = o
		return result.Report{Target: result.Target{Host: "93.184.215.14"}}
	})
	rep, err := svc.Scan(context.Background(), ScanRequest{
		Target: mustTarget(t, "93.184.215.14"), Checks: engine.Checks{Ports: true, TCP: true}, Ports: []int{22, 443},
	})
	if err != nil || rep.Target.Host != "93.184.215.14" {
		t.Fatalf("scan: %+v %v", rep, err)
	}
	if got.Dialer == nil || got.Dialer.Control == nil {
		t.Error("scan must dial through the guard's dialer")
	}
	if !got.DisableProxy {
		t.Error("proxies must be bypassed while the guard is on")
	}
	if got.Concurrency != scanConcurrency || len(got.Ports) != 2 || !got.Checks.Ports || got.Checks.HTTP {
		t.Errorf("options = %+v", got)
	}
}

func TestScanRefusesPrivateTargetsByDefault(t *testing.T) {
	svc := scanService(t, false, func(context.Context, result.Target, engine.Options) result.Report {
		t.Error("runner called for a blocked target")
		return result.Report{}
	})
	_, err := svc.Scan(context.Background(), ScanRequest{Target: mustTarget(t, "192.168.1.1"), Checks: engine.All()})
	var blocked *safety.BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("err = %v, want a BlockedError", err)
	}
}

func TestScanAllowsPrivateWhenEnabled(t *testing.T) {
	ran := false
	svc := scanService(t, true, func(_ context.Context, _ result.Target, o engine.Options) result.Report {
		ran = true
		if o.DisableProxy {
			t.Error("proxy settings should be honoured when the guard is off")
		}
		return result.Report{}
	})
	if _, err := svc.Scan(context.Background(), ScanRequest{Target: mustTarget(t, "192.168.1.1"), Checks: engine.All()}); err != nil || !ran {
		t.Fatalf("err=%v ran=%v", err, ran)
	}
}

func TestOnlyOneScanAtATime(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	svc := scanService(t, true, func(context.Context, result.Target, engine.Options) result.Report {
		once.Do(func() { close(started) })
		<-release
		return result.Report{}
	})
	go svc.Scan(context.Background(), ScanRequest{Target: mustTarget(t, "10.0.0.1"), Checks: engine.All()})
	<-started
	if _, err := svc.Scan(context.Background(), ScanRequest{Target: mustTarget(t, "10.0.0.2"), Checks: engine.All()}); !errors.Is(err, ErrScanBusy) {
		t.Fatalf("second scan: %v, want ErrScanBusy", err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := svc.Scan(context.Background(), ScanRequest{Target: mustTarget(t, "10.0.0.3"), Checks: engine.All()})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scan lock never released")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCheckAllowed(t *testing.T) {
	svc := scanService(t, false, nil)
	var blocked *safety.BlockedError
	if err := svc.CheckAllowed(context.Background(), "http://127.0.0.1:8080/"); !errors.As(err, &blocked) {
		t.Errorf("loopback: %v", err)
	}
	if err := svc.CheckAllowed(context.Background(), "1.1.1.1:53"); err != nil {
		t.Errorf("public IP: %v", err)
	}
	if err := svc.CheckAllowed(context.Background(), "ftp://x"); err == nil || errors.As(err, &blocked) {
		t.Errorf("invalid target should be a parse error, got %v", err)
	}
}
