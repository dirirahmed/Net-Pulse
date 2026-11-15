package api

import (
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/ai"
	"github.com/dirirahmed/Net-Pulse/internal/analyzer"
	"github.com/dirirahmed/Net-Pulse/internal/config"
	"github.com/dirirahmed/Net-Pulse/internal/models"
	"github.com/dirirahmed/Net-Pulse/internal/netwatch"
	"github.com/dirirahmed/Net-Pulse/internal/result"
)

// Response shapes. Telemetry structs from models are embedded as-is; these
// types only add the context each endpoint needs (ranges, summaries, status).

type SystemResponse struct {
	Host         models.HostInfo          `json:"host"`
	Timestamp    time.Time                `json:"timestamp"`
	Uptime       uint64                   `json:"uptimeSeconds"`
	Health       analyzer.HealthReport    `json:"health"`
	CPU          models.CPUStats          `json:"cpu"`
	Memory       models.MemoryStats       `json:"memory"`
	GPU          models.GPUReport         `json:"gpu"`
	Disks        []models.DiskStats       `json:"disks"`
	DiskIO       models.DiskIO            `json:"diskIO"`
	Network      models.NetworkStats      `json:"network"`
	ActiveAlerts []models.Alert           `json:"activeAlerts"`
	Collectors   []models.CollectorStatus `json:"collectors"`
	Agent        models.AgentStats        `json:"agent"`
}

type ComponentResponse[T any] struct {
	Timestamp time.Time      `json:"timestamp"`
	Current   T              `json:"current"`
	Range     string         `json:"range,omitempty"`
	Summary   *analyzer.Stat `json:"summary,omitempty"`
}

type NetworkResponse struct {
	Timestamp time.Time           `json:"timestamp"`
	Current   models.NetworkStats `json:"current"`
	Range     string              `json:"range"`
	Download  analyzer.Stat       `json:"download"`
	Upload    analyzer.Stat       `json:"upload"`
}

type DisksResponse struct {
	Timestamp time.Time          `json:"timestamp"`
	Disks     []models.DiskStats `json:"disks"`
	IO        models.DiskIO      `json:"io"`
}

type MetricsResponse struct {
	Range         string                  `json:"range"`
	BucketSeconds float64                 `json:"bucketSeconds"`
	Points        []models.HistoryPoint   `json:"points"`
	Summary       analyzer.SeriesSummary  `json:"summary"`
	Disks         []models.DiskUsagePoint `json:"disks,omitempty"`
	DisksError    string                  `json:"disksError,omitempty"`
}

type ProcessesResponse struct {
	Timestamp time.Time        `json:"timestamp"`
	Count     int              `json:"count"`
	Processes []models.Process `json:"processes"`
	Note      string           `json:"note"`
}

type AlertsResponse struct {
	Active  []models.Alert `json:"active"`
	History []models.Alert `json:"history"`
	// HistoryError is set when stored history couldn't be read; active
	// alerts are still returned from memory.
	HistoryError string `json:"historyError,omitempty"`
}

type SettingsResponse struct {
	Config          config.Config `json:"config"`
	RestartRequired []string      `json:"restartRequired,omitempty"`
}

// AnalysisResponse is GET /api/analysis (V2).
type AnalysisResponse struct {
	Analysis analyzer.PerformanceReport `json:"analysis"`
	AI       AIStatus                   `json:"ai"`
}

// AIStatus tells the UI whether Ask Pulse is available. It never includes
// the API key.
type AIStatus struct {
	Enabled bool   `json:"enabled"`
	Model   string `json:"model,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// AskRequest is the body of POST /api/ai/ask. History holds earlier turns of
// the conversation (oldest first); the server trims and validates it.
type AskRequest struct {
	Question string    `json:"question"`
	History  []ai.Turn `json:"history,omitempty"`
}

type AskResponse struct {
	Answer      string    `json:"answer"`
	Model       string    `json:"model"`
	GeneratedAt time.Time `json:"generatedAt"`
	// Analysis is the data the answer was based on.
	Analysis analyzer.PerformanceReport `json:"analysis"`
}

// ---- network monitoring and diagnostics ----

// TargetView is one monitored target with its 24-hour uptime.
type TargetView struct {
	netwatch.TargetStatus
	// Uptime24h is the share of checks in the last 24 hours that reached the
	// target (up or degraded); nil without history or before any check.
	Uptime24h *float64 `json:"uptime24h"`
	Checks24h int      `json:"checks24h"`
}

type TargetsResponse struct {
	Targets              []TargetView `json:"targets"`
	AllowPrivateTargets  bool         `json:"allowPrivateTargets"`
	CheckIntervalSeconds int          `json:"checkIntervalSeconds"`
	MaxTargets           int          `json:"maxTargets"`
	HistoryAvailable     bool         `json:"historyAvailable"`
	HistoryError         string       `json:"historyError,omitempty"`
}

type AddTargetRequest struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

type TargetHistoryResponse struct {
	ID            string                 `json:"id"`
	Range         string                 `json:"range"`
	BucketSeconds float64                `json:"bucketSeconds"`
	Points        []models.NetCheckPoint `json:"points"`
	Uptime        models.NetUptime       `json:"uptime"`
	UptimePercent *float64               `json:"uptimePercent"`
}

// ScanRequest is the body of POST /api/scan. Checks defaults to all of
// dns, ports, tcp, tls and http; Ports takes the same spec as the CLI's
// -ports flag and is capped at netwatch.MaxScanPorts.
type ScanRequest struct {
	Target string   `json:"target"`
	Checks []string `json:"checks,omitempty"`
	Ports  string   `json:"ports,omitempty"`
}

type ScanResponse struct {
	Report result.Report `json:"report"`
}

type errorResponse struct {
	Error string `json:"error"`
	// Blocked marks a target refused by the private-address guard, so the
	// UI can point at the setting.
	Blocked bool `json:"blocked,omitempty"`
}
