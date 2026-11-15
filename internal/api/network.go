package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/engine"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/netwatch"
	"github.com/dirirahmed/Net-Pulse/internal/probe"
	"github.com/dirirahmed/Net-Pulse/internal/result"
	"github.com/dirirahmed/Net-Pulse/internal/safety"
)

// Network is the read/write side of scheduled network monitoring and
// on-demand diagnostics. *netwatch.Service implements it.
type Network interface {
	Targets() []netwatch.TargetStatus
	Target(id string) (netwatch.TargetStatus, bool)
	CheckNow(id string) error
	ActiveAlerts() []models.Alert
	History(ctx context.Context, id string, period time.Duration, maxPoints int) ([]models.NetCheckPoint, time.Duration, error)
	Uptime(ctx context.Context, id string, period time.Duration) (models.NetUptime, error)
	Scan(ctx context.Context, req netwatch.ScanRequest) (result.Report, error)
	CheckAllowed(ctx context.Context, raw string) error
	Reconfigure()
}

// WithNetwork enables the /api/targets and /api/scan endpoints.
func (s *Server) WithNetwork(n Network) *Server {
	s.net = n
	return s
}

const (
	maxHistoryPoints = 300
	uptimeWindow     = 24 * time.Hour
	privateHint      = "Turn on \"Allow private targets\" in Settings to reach loopback and LAN addresses."
	demoPrivateHint  = "The live demo never reaches loopback, private or cloud metadata addresses."
)

func (s *Server) networkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/targets", s.handleTargets)
	mux.HandleFunc("POST /api/targets", s.handleAddTarget)
	mux.HandleFunc("DELETE /api/targets/{id}", s.handleDeleteTarget)
	mux.HandleFunc("GET /api/targets/{id}/history", s.handleTargetHistory)
	mux.HandleFunc("POST /api/targets/{id}/check", s.handleCheckNow)
	mux.HandleFunc("POST /api/scan", s.handleScan)
}

// requireNetwork writes 503 when network monitoring isn't wired in.
func (s *Server) requireNetwork(w http.ResponseWriter) bool {
	if s.net == nil {
		writeError(w, http.StatusServiceUnavailable, "network monitoring is not available")
		return false
	}
	return true
}

// requireJSON blocks cross-site form posts, which can't send this type.
func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	if !s.requireNetwork(w) {
		return
	}
	n := s.cfg.Get().Network
	resp := TargetsResponse{
		Targets: []TargetView{}, AllowPrivateTargets: n.AllowPrivateTargets,
		CheckIntervalSeconds: n.CheckIntervalSeconds, MaxTargets: config.MaxTargets, HistoryAvailable: true,
	}
	for _, t := range s.net.Targets() {
		v := TargetView{TargetStatus: t}
		u, err := s.net.Uptime(r.Context(), t.ID, uptimeWindow)
		if err != nil {
			// Live status still works without the database.
			resp.HistoryAvailable, resp.HistoryError = false, err.Error()
		} else {
			v.Uptime24h, v.Checks24h = u.Percent(), u.Checks
		}
		resp.Targets = append(resp.Targets, v)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAddTarget(w http.ResponseWriter, r *http.Request) {
	if !s.requireNetwork(w) || s.readOnly(w) || !requireJSON(w, r) {
		return
	}
	var req AddTargetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name, req.Target = strings.TrimSpace(req.Name), strings.TrimSpace(req.Target)
	if req.Name == "" {
		req.Name = req.Target
	}
	if _, err := engine.ParseTarget(req.Target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Refuse a target the guard would block on every check, with the reason,
	// instead of saving something that can never work.
	if err := s.net.CheckAllowed(r.Context(), req.Target); err != nil {
		s.writeBlocked(w, err)
		return
	}

	next := s.cfg.Get()
	t := config.NetTarget{ID: uniqueID(slugify(req.Name), next.Network.Targets), Name: req.Name, Target: req.Target}
	next.Network.Targets = append(next.Network.Targets, t)
	if err := next.Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.cfg.Update(next); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.net.Reconfigure()
	s.log.Info("network target added", "id", t.ID, "target", t.Target)
	status, _ := s.net.Target(t.ID)
	writeJSON(w, http.StatusCreated, TargetView{TargetStatus: status})
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if !s.requireNetwork(w) || s.readOnly(w) {
		return
	}
	id := r.PathValue("id")
	next := s.cfg.Get()
	kept := next.Network.Targets[:0]
	for _, t := range next.Network.Targets {
		if t.ID != id {
			kept = append(kept, t)
		}
	}
	if len(kept) == len(next.Network.Targets) {
		writeError(w, http.StatusNotFound, "unknown target")
		return
	}
	next.Network.Targets = kept
	if err := s.cfg.Update(next); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.net.Reconfigure()
	s.log.Info("network target removed", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTargetHistory(w http.ResponseWriter, r *http.Request) {
	if !s.requireNetwork(w) {
		return
	}
	id := r.PathValue("id")
	name, period, err := parseRange(r, "24h")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pts, bucket, err := s.net.History(r.Context(), id, period, maxHistoryPoints)
	switch {
	case errors.Is(err, netwatch.ErrUnknownTarget):
		writeError(w, http.StatusNotFound, "unknown target")
		return
	case errors.Is(err, netwatch.ErrNoHistory):
		writeError(w, http.StatusServiceUnavailable, "history unavailable: "+err.Error())
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "history unavailable: "+err.Error())
		return
	}
	resp := TargetHistoryResponse{ID: id, Range: name, BucketSeconds: bucket.Seconds(), Points: pts}
	if u, err := s.net.Uptime(r.Context(), id, period); err == nil {
		resp.Uptime, resp.UptimePercent = u, u.Percent()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCheckNow(w http.ResponseWriter, r *http.Request) {
	if !s.requireNetwork(w) || !requireJSON(w, r) {
		return
	}
	if err := s.net.CheckNow(r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "unknown target")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scheduled"})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.requireNetwork(w) || !requireJSON(w, r) {
		return
	}
	var req ScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	target, err := engine.ParseTarget(req.Target)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	checks, err := engine.ParseChecks(strings.Join(req.Checks, ","))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ports []int
	if checks.Ports {
		spec := req.Ports
		if strings.TrimSpace(spec) == "" {
			spec = "default"
		}
		if ports, err = probe.ParsePorts(spec); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		limit := netwatch.MaxScanPorts
		if s.demo {
			limit = demoMaxScanPorts
		}
		if len(ports) > limit {
			writeError(w, http.StatusBadRequest, fmt.Sprintf(
				"%d ports requested; the dashboard scans at most %d (use `netpulse scan` for larger scans)", len(ports), limit))
			return
		}
	}
	if s.scanLimit != nil && !s.scanLimit.allow() {
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf(
			"The live demo allows %d scans a minute across all visitors. Try again shortly.", demoScansPerMinute))
		return
	}

	rep, err := s.net.Scan(r.Context(), netwatch.ScanRequest{Target: target, Checks: checks, Ports: ports})
	switch {
	case errors.Is(err, netwatch.ErrScanBusy):
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		s.writeBlocked(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ScanResponse{Report: rep})
}

// writeBlocked reports a guard refusal as 422 with a hint, and anything else
// as a bad request.
func (s *Server) writeBlocked(w http.ResponseWriter, err error) {
	var blocked *safety.BlockedError
	if errors.As(err, &blocked) {
		hint := privateHint
		if s.demo {
			hint = demoPrivateHint
		}
		writeJSON(w, http.StatusUnprocessableEntity, errorResponse{Error: blocked.Error() + ". " + hint, Blocked: true, Demo: s.demo})
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}

// activeAlerts merges system and network alerts, most severe first.
func (s *Server) activeAlerts() []models.Alert {
	out := s.src.ActiveAlerts()
	if s.net == nil {
		return out
	}
	out = append(out, s.net.ActiveAlerts()...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}

// slugify turns a display name into a target id: lowercase letters, digits
// and single dashes, at most 32 characters.
func slugify(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 32 {
			break
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		return "target"
	}
	return id
}

// uniqueID appends -2, -3, ... until id is unused.
func uniqueID(id string, existing []config.NetTarget) string {
	taken := map[string]bool{}
	for _, t := range existing {
		taken[t.ID] = true
	}
	if !taken[id] {
		return id
	}
	for i := 2; ; i++ {
		c := id + "-" + strconv.Itoa(i)
		if !taken[c] {
			return c
		}
	}
}
