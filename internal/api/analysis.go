package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dirirahmed/Net-Pulse/internal/ai"
	"github.com/dirirahmed/Net-Pulse/internal/analyzer"
	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/netwatch"
)

// V2: performance analysis and the optional AI assistant.

// Assistant answers questions about the PC. *ai.Client implements it; a nil
// Assistant means the feature is off.
type Assistant interface {
	Enabled() bool
	Model() string
	Ask(ctx context.Context, q ai.Question) (ai.Answer, error)
}

// WithAssistant enables POST /api/ai/ask. Monitoring works without it.
func (s *Server) WithAssistant(a Assistant) *Server {
	s.ai = a
	return s
}

const (
	maxQuestionChars   = 1000
	maxHistoryTurns    = 8
	maxHistoryChars    = 4000 // per turn
	topProcessesForAI  = 5
	processListTimeout = 10 * time.Second
)

// analysisData is one consistent read of everything the analysis and the
// AI context need.
type analysisData struct {
	snap    models.Snapshot
	report  analyzer.PerformanceReport
	procs   []models.Process        // nil when unavailable
	targets []netwatch.TargetStatus // nil when network monitoring is off
	network []analyzer.NetTarget    // the same targets as the analysis saw them
}

func (s *Server) collectAnalysis(ctx context.Context) (analysisData, bool) {
	snap, ok := s.src.Snapshot()
	if !ok {
		return analysisData{}, false
	}
	// Both reads degrade gracefully: missing history or processes turn into
	// "check skipped" notes rather than errors.
	pts, _, err := s.src.Series(ctx, analyzer.AnalysisWindow)
	if err != nil {
		pts = nil
	}
	pctx, cancel := context.WithTimeout(ctx, processListTimeout)
	defer cancel()
	procs, err := s.src.Processes(pctx)
	if err != nil {
		procs = nil
	} else if procs == nil {
		procs = []models.Process{}
	}
	cfg := s.cfg.Get()
	targets, network := s.networkInput(ctx)
	report := analyzer.AnalyzePerformance(analyzer.PerformanceInput{
		Now: time.Now().UTC(), Points: pts, Snapshot: &snap, Processes: procs,
		DiskFree: cfg.Thresholds.DiskFreePercent,
		Network:  network, NetworkSettings: cfg.Network,
	})
	return analysisData{snap: snap, report: report, procs: procs, targets: targets, network: network}, true
}

// networkInput reads the monitored targets for the analysis. Both results
// are nil when network monitoring isn't wired in.
func (s *Server) networkInput(ctx context.Context) ([]netwatch.TargetStatus, []analyzer.NetTarget) {
	if s.net == nil {
		return nil, nil
	}
	targets := s.net.Targets()
	out := make([]analyzer.NetTarget, 0, len(targets))
	for _, t := range targets {
		nt := analyzer.NetTarget{Name: t.Name, Status: t.Status, ConsecutiveFailures: t.ConsecutiveFailures}
		if t.Last != nil {
			nt.Reason, nt.ResponseMs, nt.HTTPStatus = t.Last.Reason, t.Last.ResponseMs, t.Last.HTTPStatus
		}
		// The latest known certificate expiry, even if the last check failed.
		for i := len(t.Recent) - 1; i >= 0; i-- {
			if t.Recent[i].CertDaysLeft != nil {
				nt.CertDaysLeft = t.Recent[i].CertDaysLeft
				break
			}
		}
		if u, err := s.net.Uptime(ctx, t.ID, uptimeWindow); err == nil {
			nt.Uptime24h, nt.Checks24h = u.Percent(), u.Checks
		}
		out = append(out, nt)
	}
	return targets, out
}

func (s *Server) aiStatus() AIStatus {
	if s.demo {
		return AIStatus{Enabled: false, Reason: demoAIMsg}
	}
	if s.ai == nil || !s.ai.Enabled() {
		return AIStatus{Enabled: false, Reason: "Set the " + ai.EnvAPIKey + " environment variable and restart Net-Pulse to enable Ask Pulse."}
	}
	return AIStatus{Enabled: true, Model: s.ai.Model()}
}

func (s *Server) handleAnalysis(w http.ResponseWriter, r *http.Request) {
	d, ok := s.collectAnalysis(r.Context())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "first sample not collected yet; retry shortly")
		return
	}
	writeJSON(w, http.StatusOK, AnalysisResponse{Analysis: d.report, AI: s.aiStatus()})
}

func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	if s.demo {
		writeError(w, http.StatusServiceUnavailable, demoAIMsg)
		return
	}
	if s.ai == nil || !s.ai.Enabled() {
		writeError(w, http.StatusServiceUnavailable, ai.ErrDisabled.Error())
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var req AskRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request JSON: "+err.Error())
		return
	}
	question := strings.TrimSpace(req.Question)
	if question == "" {
		writeError(w, http.StatusBadRequest, "question must not be empty")
		return
	}
	if utf8.RuneCountInString(question) > maxQuestionChars {
		writeError(w, http.StatusBadRequest, "question is too long (max 1000 characters)")
		return
	}

	d, ok := s.collectAnalysis(r.Context())
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "first sample not collected yet; retry shortly")
		return
	}
	ans, err := s.ai.Ask(r.Context(), ai.Question{Text: question, History: sanitizeHistory(req.History), Data: s.aiContext(d)})
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, ai.ErrDisabled):
			status = http.StatusServiceUnavailable
		case errors.Is(err, context.DeadlineExceeded):
			status = http.StatusGatewayTimeout
		}
		s.log.Warn("ask pulse failed", "err", err)
		writeError(w, status, "AI request failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, AskResponse{Answer: ans.Text, Model: ans.Model, GeneratedAt: time.Now().UTC(), Analysis: d.report})
}

// sanitizeHistory keeps the most recent well-formed turns, starting with a
// user turn as the Messages API expects.
func sanitizeHistory(in []ai.Turn) []ai.Turn {
	out := []ai.Turn{}
	for _, t := range in {
		t.Content = strings.TrimSpace(t.Content)
		if (t.Role != "user" && t.Role != "assistant") || t.Content == "" {
			continue
		}
		if r := []rune(t.Content); len(r) > maxHistoryChars {
			t.Content = string(r[:maxHistoryChars])
		}
		out = append(out, t)
	}
	if len(out) > maxHistoryTurns {
		out = out[len(out)-maxHistoryTurns:]
	}
	for len(out) > 0 && out[0].Role != "user" {
		out = out[1:]
	}
	// The new question is a user turn, so history must end with the assistant.
	if len(out) > 0 && out[len(out)-1].Role == "user" {
		out = out[:len(out)-1]
	}
	return out
}

// aiContext picks what the model may see. Hostname, executable paths and
// anything else that identifies the user are deliberately left out.
func (s *Server) aiContext(d analysisData) ai.Context {
	snap := d.snap
	host := s.src.Host()
	health := s.src.Health()
	c := ai.Context{
		System: ai.SystemInfo{
			OS:       strings.TrimSpace(host.Platform + " " + host.PlatformVersion),
			CPUModel: snap.CPU.Model, PhysicalCores: snap.CPU.PhysicalCores, LogicalCores: snap.CPU.LogicalCores,
			CPUNowPercent: snap.CPU.UsagePercent, CPUTemperatureC: snap.CPU.TemperatureC,
			MemoryTotalBytes: snap.Memory.TotalBytes, MemoryUsedPercent: snap.Memory.UsedPercent,
			GPUs: []ai.GPU{}, Drives: []ai.Drive{}, UptimeSeconds: snap.UptimeSeconds,
		},
		Analysis:     d.report,
		Health:       ai.HealthInfo{Score: health.Overall, Grade: health.Grade, Summary: health.Summary},
		ActiveAlerts: []ai.AlertInfo{},
	}
	for _, v := range snap.CPU.PerCorePercent {
		if c.System.BusiestCorePercent == nil || v > *c.System.BusiestCorePercent {
			core := v
			c.System.BusiestCorePercent = &core
		}
	}
	if !snap.GPU.Available {
		c.System.GPUUnavailable = snap.GPU.Reason
	}
	for _, g := range snap.GPU.Adapters {
		c.System.GPUs = append(c.System.GPUs, ai.GPU{Name: g.Name, UsagePercent: g.UsagePercent,
			MemoryUsedBytes: g.MemoryUsedBytes, MemoryTotalBytes: g.MemoryTotalBytes, TemperatureC: g.TemperatureC})
	}
	for _, dk := range snap.Disks {
		c.System.Drives = append(c.System.Drives, ai.Drive{Mountpoint: dk.Mountpoint, TotalBytes: dk.TotalBytes, FreePercent: dk.FreePercent})
	}
	labels := aiLabels(d.targets)
	c.Analysis = redactReport(d.report, labels)
	for _, a := range s.activeAlerts() {
		info := ai.AlertInfo{Severity: string(a.Severity), Title: a.Title, Reason: a.Reason}
		if a.Component == "network" {
			info = networkAlertForAI(a, labels)
		}
		c.ActiveAlerts = append(c.ActiveAlerts, info)
	}
	if d.network != nil {
		c.NetworkTargets = []ai.NetTargetInfo{}
		for _, t := range d.network {
			c.NetworkTargets = append(c.NetworkTargets, ai.NetTargetInfo{
				Name: labels.of(t.Name), Status: string(t.Status), Reason: t.Reason, ConsecutiveFailures: t.ConsecutiveFailures,
				LastResponseMs: t.ResponseMs, HTTPStatus: t.HTTPStatus, CertDaysLeft: t.CertDaysLeft, Uptime24hPercent: t.Uptime24h,
			})
		}
	}
	if d.procs != nil {
		c.TopByCPU = analyzer.TopProcesses(d.procs, true, topProcessesForAI)
		c.TopByMemory = analyzer.TopProcesses(d.procs, false, topProcessesForAI)
	}
	return c
}

// ---- keeping monitored addresses away from the model ----

// targetLabels maps a target's display name to what the model may see.
type targetLabels map[string]string

func (l targetLabels) of(name string) string {
	if v, ok := l[name]; ok {
		return v
	}
	return name
}

// aiLabels keeps names the user chose and replaces any name that reveals the
// target's address (an unnamed target is named after its address) with
// "Monitored target N". Hostnames are kept from the model like the PC's own.
func aiLabels(targets []netwatch.TargetStatus) targetLabels {
	labels := targetLabels{}
	for i, t := range targets {
		label := t.Name
		if revealsAddress(t.Name, t.Target) {
			label = fmt.Sprintf("Monitored target %d", i+1)
		}
		labels[t.Name] = label
	}
	return labels
}

func revealsAddress(name, target string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, strings.ToLower(target)) {
		return true
	}
	t, err := engine.ParseTarget(target)
	return err == nil && strings.Contains(n, strings.ToLower(t.Host))
}

// redactReport returns a copy of the report with network findings relabelled.
// Network evidence is built from names and coarse reasons only, so names are
// the one thing that can carry an address.
func redactReport(r analyzer.PerformanceReport, labels targetLabels) analyzer.PerformanceReport {
	var pairs []string
	for name, label := range labels {
		if name != label {
			pairs = append(pairs, name, label)
		}
	}
	if len(pairs) == 0 {
		return r
	}
	// Longest names first, so "api.example.com:8443" is replaced before "api.example.com".
	type pair struct{ from, to string }
	ps := make([]pair, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		ps = append(ps, pair{pairs[i], pairs[i+1]})
	}
	sort.Slice(ps, func(i, j int) bool { return len(ps[i].from) > len(ps[j].from) })
	flat := make([]string, 0, len(pairs))
	for _, p := range ps {
		flat = append(flat, p.from, p.to)
	}
	rep := strings.NewReplacer(flat...)

	out := r
	out.Findings = make([]analyzer.Finding, len(r.Findings))
	for i, f := range r.Findings {
		if f.Category == "network" {
			f.Target = labels.of(f.Target)
			f.ID, f.Title, f.Evidence = rep.Replace(f.ID), rep.Replace(f.Title), rep.Replace(f.Evidence)
			f.Explanation, f.Recommendation = rep.Replace(f.Explanation), rep.Replace(f.Recommendation)
		}
		out.Findings[i] = f
	}
	out.Recommendations = make([]string, len(r.Recommendations))
	for i, rec := range r.Recommendations {
		out.Recommendations[i] = rep.Replace(rec)
	}
	out.Summary = rep.Replace(r.Summary)
	return out
}

// networkAlertForAI rewrites a network alert without its stored reason, which
// quotes the raw error (and with it resolved IP addresses).
func networkAlertForAI(a models.Alert, labels targetLabels) ai.AlertInfo {
	name := labels.of(a.Target)
	info := ai.AlertInfo{Severity: string(a.Severity)}
	switch a.Rule {
	case "net_down":
		info.Title = name + " is unreachable"
		info.Reason = fmt.Sprintf("%s failed %.0f checks in a row.", name, a.Value)
	case "net_slow":
		info.Title = name + " is responding slowly"
		info.Reason = fmt.Sprintf("%s was slow on %.0f checks in a row.", name, a.Value)
	case "net_cert_expiry":
		info.Title = name + " TLS certificate"
		if a.Value < 0 {
			info.Reason = fmt.Sprintf("The TLS certificate for %s has expired.", name)
		} else {
			info.Reason = fmt.Sprintf("The TLS certificate for %s expires in %.0f days.", name, a.Value)
		}
	default:
		info.Title = name + ": network alert"
		info.Reason = "A network check for " + name + " raised an alert."
	}
	return info
}
