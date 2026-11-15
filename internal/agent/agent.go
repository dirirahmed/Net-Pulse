// Package agent runs the long-lived monitoring agent behind `netpulse serve`:
// it wires the collectors, monitor, history database, API and embedded
// dashboard together and serves them on a local-only HTTP port.
package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/ai"
	"github.com/dirirahmed/Net-Pulse/internal/api"
	"github.com/dirirahmed/Net-Pulse/internal/collector"
	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/monitor"
	"github.com/dirirahmed/Net-Pulse/internal/netwatch"
	"github.com/dirirahmed/Net-Pulse/internal/storage"
	"github.com/dirirahmed/Net-Pulse/web"
)

// Version is the build version, set by cmd/netpulse; logged at start-up.
var Version = "dev"

// Run parses the serve flags and runs the agent until ctx is cancelled.
func Run(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("netpulse serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for config.json and the history database")
	configPath := fs.String("config", "", "config file path (default <data-dir>/config.json)")
	port := fs.Int("port", 0, "override the configured API port")
	openBrowser := fs.Bool("open", runtime.GOOS == "windows", "open the dashboard in the default browser on start")
	demo := fs.Bool("demo", os.Getenv(EnvDemo) == "1",
		"run as a public read-only demo: listen on all interfaces (port from $PORT), never save settings, force the private-address guard on, disable Ask Pulse")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage:\n  netpulse serve [flags]\n\nRuns the monitoring agent and serves the dashboard.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("serve takes no arguments, got %q", fs.Args())
	}

	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *configPath == "" {
		*configPath = filepath.Join(*dataDir, "config.json")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		// A broken config file shouldn't stop monitoring; defaults are safe.
		log.Error("using default settings", "err", err)
	}
	storePath := *configPath
	if *demo {
		*port = demoPort(*port)
		applyDemo(&cfg)
		*openBrowser = false
		storePath = "" // the demo never writes its config back
	}
	if *port != 0 {
		cfg.Port = *port
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	cfgStore := config.NewStore(storePath, cfg)

	// Bind before touching the database so a second instance fails fast
	// instead of sharing (and closing alerts in) the first one's history.
	addr := net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s (is the agent already running?): %w", addr, err)
	}

	ctx, stop := context.WithCancel(ctx)
	defer stop()

	var store monitor.Store
	var netStore netwatch.Store // stays a nil interface when the database is unavailable
	dbPath := filepath.Join(*dataDir, "history.db")
	db, dbErr := storage.Open(dbPath)
	if dbErr != nil {
		log.Error("history database unavailable; continuing with live data only", "path", dbPath, "err", dbErr)
	} else {
		defer db.Close()
		store, netStore = db, db
		if n, err := db.CloseDanglingAlerts(ctx, time.Now()); err == nil && n > 0 {
			log.Info("closed alerts left open by previous run", "count", n)
		}
	}

	col := collector.New(ctx, log)
	defer col.Close()
	mon := monitor.New(monitor.Options{
		Config: cfgStore, Collector: col, Processes: collector.NewProcessSampler(),
		Store: store, StoreErr: dbErr, Host: collector.HostInfo(ctx), Logger: log,
	})

	// Scheduled checks of the configured network targets run beside the
	// system monitor and share its database and alert history.
	nw := netwatch.New(netwatch.Options{Config: cfgStore, Store: netStore, Logger: log})
	log.Info("network monitoring", "targets", len(cfg.Network.Targets), "allowPrivateTargets", cfg.Network.AllowPrivateTargets)

	static, bundled := web.Dist()
	if !bundled {
		log.Warn("frontend not bundled; API only (run `npm run build` in web/ before `go build` to embed it)")
	}
	handler := api.New(mon, cfgStore, static, log).WithNetwork(nw).WithDemo(*demo)
	if *demo {
		// A public demo must not spend anyone's API credit, so the key is
		// not even read.
		log.Info("demo mode: read-only settings and targets, private targets blocked, Ask Pulse off")
	} else {
		// Ask Pulse is optional: without an API key it stays off and
		// monitoring is unaffected. The key is only read here, never logged.
		assistant := ai.New(ai.ConfigFromEnv())
		if assistant.Enabled() {
			log.Info("Ask Pulse enabled", "model", assistant.Model())
		} else {
			log.Info("Ask Pulse disabled; set " + ai.EnvAPIKey + " to enable it")
		}
		handler.WithAssistant(assistant)
	}
	srv := &http.Server{
		Handler:           handler.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// A scan may run for up to 60 s before its response is written.
		WriteTimeout:   90 * time.Second,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
	}

	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()
	netDone := make(chan struct{})
	go func() {
		nw.Run(ctx)
		close(netDone)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server stopped", "err", err)
			stop()
		}
	}()

	url := "http://" + dashboardHost(cfg.ListenAddress) + ":" + strconv.Itoa(cfg.Port)
	log.Info("Net-Pulse running", "version", Version, "dashboard", url, "data", *dataDir)
	if *openBrowser && bundled {
		openURL(url)
	}

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	<-done
	<-netDone
	return nil
}

// EnvDemo set to "1" turns on -demo, for container platforms where flags are
// awkward to change.
const EnvDemo = "NETPULSE_DEMO"

// demoPort picks the port for demo mode: an explicit -port wins, then the
// $PORT that hosting platforms (Render, Cloud Run, Koyeb, ...) assign.
func demoPort(flagPort int) int {
	if flagPort != 0 {
		return flagPort
	}
	if p, err := strconv.Atoi(os.Getenv("PORT")); err == nil && p > 0 && p <= 65535 {
		return p
	}
	return 0
}

// applyDemo makes a loaded config safe to serve publicly.
func applyDemo(cfg *config.Config) {
	cfg.ListenAddress = "0.0.0.0"
	// Whatever the file says, a public page must not reach the host's
	// private network or cloud metadata endpoints.
	cfg.Network.AllowPrivateTargets = false
}

// Data directory names under the user config dir (%APPDATA% on Windows).
const (
	dataDirName       = "NetPulse"
	legacyDataDirName = "PCSentinel" // used before PC Sentinel merged into Net-Pulse
)

func defaultDataDir() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "netpulse-data"
	}
	return pickDataDir(dir)
}

// pickDataDir keeps an existing PC Sentinel install's settings and history:
// the legacy directory is reused until a NetPulse directory exists.
func pickDataDir(base string) string {
	current := filepath.Join(base, dataDirName)
	legacy := filepath.Join(base, legacyDataDirName)
	if _, err := os.Stat(current); err != nil {
		if info, err := os.Stat(legacy); err == nil && info.IsDir() {
			return legacy
		}
	}
	return current
}

func dashboardHost(listen string) string {
	if listen == "0.0.0.0" || listen == "::" || listen == "" {
		return "localhost"
	}
	return listen
}

func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
