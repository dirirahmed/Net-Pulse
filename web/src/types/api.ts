// Mirrors the Go API response shapes (internal/api/dto.go, internal/models).
// `null` always means "not available on this machine", never zero.

export type Severity = "info" | "warning" | "critical";
export type Grade = "good" | "fair" | "poor" | "critical" | "unavailable";
export type SpaceStatus = "ok" | "warning" | "critical";

export interface HostInfo {
  hostname: string;
  os: string;
  platform: string;
  platformVersion: string;
  kernelArch: string;
  bootTime: string;
}

export interface CPUStats {
  model: string;
  physicalCores: number;
  logicalCores: number;
  baseFrequencyMHz: number | null;
  currentFrequencyMHz: number | null;
  usagePercent: number;
  perCorePercent: number[] | null;
  temperatureC: number | null;
  temperatureSource?: string;
}

export interface MemoryStats {
  totalBytes: number;
  usedBytes: number;
  availableBytes: number;
  usedPercent: number;
}

export interface GPUEngine {
  name: string;
  usagePercent: number;
}

export interface GPUStats {
  name: string;
  vendor: string;
  usagePercent: number | null;
  memoryUsedBytes: number | null;
  memoryTotalBytes: number | null;
  temperatureC: number | null;
  temperatureSource?: string;
  engines: GPUEngine[];
}

export interface GPUReport {
  available: boolean;
  reason?: string;
  source?: string;
  adapters: GPUStats[];
}

export interface DiskStats {
  mountpoint: string;
  device: string;
  fsType: string;
  totalBytes: number;
  usedBytes: number;
  freeBytes: number;
  usedPercent: number;
  freePercent: number;
  readBytesPerSec: number | null;
  writeBytesPerSec: number | null;
  spaceStatus: SpaceStatus;
}

export interface DiskIO {
  readBytesPerSec: number | null;
  writeBytesPerSec: number | null;
}

export interface NetworkStats {
  rxBytesPerSec: number;
  txBytesPerSec: number;
  totalRxBytes: number;
  totalTxBytes: number;
  interfaces: number;
}

export interface CollectorStatus {
  name: string;
  ok: boolean;
  error?: string;
}

export interface AgentStats {
  pid: number;
  cpuPercent: number;
  avgCpuPercent: number;
  memoryRssBytes: number;
  goHeapBytes: number;
  goroutines: number;
  uptimeSeconds: number;
  avgCollectionMillis: number;
  lastCollectionMillis: number;
  storageAvailable: boolean;
  storageError?: string;
}

export interface CategoryScore {
  key: string;
  label: string;
  available: boolean;
  score: number;
  grade: Grade;
  weight: number;
  reasons: string[];
}

export interface HealthReport {
  overall: number;
  grade: Grade;
  categories: CategoryScore[];
  summary: string;
}

export interface Alert {
  id: string;
  rule: string;
  component: string;
  target?: string;
  severity: Severity;
  title: string;
  reason: string;
  value: number;
  threshold: number;
  startedAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

export interface SystemResponse {
  host: HostInfo;
  timestamp: string;
  uptimeSeconds: number;
  health: HealthReport;
  cpu: CPUStats;
  memory: MemoryStats;
  gpu: GPUReport;
  disks: DiskStats[];
  diskIO: DiskIO;
  network: NetworkStats;
  activeAlerts: Alert[];
  collectors: CollectorStatus[];
  agent: AgentStats;
}

export interface HistoryPoint {
  t: string;
  cpu: number;
  cpuMax: number;
  memory: number;
  memoryUsed: number;
  gpu: number | null;
  gpuMax: number | null;
  cpuTemp: number | null;
  gpuTemp: number | null;
  netRx: number;
  netTx: number;
  diskRead: number | null;
  diskWrite: number | null;
}

export interface Stat {
  available: boolean;
  avg: number;
  peak: number;
  current: number;
}

export interface SeriesSummary {
  cpu: Stat;
  memory: Stat;
  gpu: Stat;
  cpuTemp: Stat;
  gpuTemp: Stat;
  netRx: Stat;
  netTx: Stat;
  diskRead: Stat;
  diskWrite: Stat;
}

export interface DiskUsagePoint {
  t: string;
  mountpoint: string;
  usedPercent: number;
  freeBytes: number;
}

export interface MetricsResponse {
  range: string;
  bucketSeconds: number;
  points: HistoryPoint[];
  summary: SeriesSummary;
  disks?: DiskUsagePoint[];
  disksError?: string;
}

export interface Process {
  pid: number;
  name: string;
  cpuPercent: number | null;
  memoryBytes: number;
  memoryPercent: number;
  path: string;
  status: string;
}

export interface ProcessesResponse {
  timestamp: string;
  count: number;
  processes: Process[];
  note: string;
}

export interface AlertsResponse {
  active: Alert[];
  history: Alert[];
  historyError?: string;
}

export interface Threshold {
  warning: number;
  critical: number;
  sustainSeconds: number;
}

export interface Config {
  listenAddress: string;
  port: number;
  sampleIntervalSeconds: number;
  historyIntervalSeconds: number;
  retentionDays: number;
  alertCooldownSeconds: number;
  thresholds: {
    cpuUsage: Threshold;
    memoryUsage: Threshold;
    diskFreePercent: Threshold;
    cpuTemperature: Threshold;
    gpuTemperature: Threshold;
    sustainedCpu: { averagePercent: number; windowMinutes: number };
  };
  network: NetworkConfig;
}

export interface NetTargetConfig {
  id: string;
  name: string;
  target: string;
}

export interface NetworkConfig {
  allowPrivateTargets: boolean;
  checkIntervalSeconds: number;
  failuresBeforeAlert: number;
  slowResponseMs: number;
  certExpiry: { warningDays: number; criticalDays: number };
  targets: NetTargetConfig[];
}

export interface SettingsResponse {
  config: Config;
  restartRequired?: string[];
}

// ---- Performance analysis and Ask Pulse ----

export type AnalysisStatus = "ok" | "collecting" | Severity;

export interface Finding {
  id: string;
  rule: string;
  category: "cpu" | "memory" | "gpu" | "disk" | "process";
  target?: string;
  severity: Severity;
  title: string;
  explanation: string;
  evidence: string;
  value: number;
  threshold: number;
  unit: string;
  recommendation: string;
}

export interface PerformanceReport {
  generatedAt: string;
  status: AnalysisStatus;
  summary: string;
  windowSeconds: number;
  samples: number;
  metrics: SeriesSummary;
  findings: Finding[];
  recommendations: string[];
  notes: string[];
}

export interface AIStatus {
  enabled: boolean;
  model?: string;
  reason?: string;
}

export interface AnalysisResponse {
  analysis: PerformanceReport;
  ai: AIStatus;
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface AskResponse {
  answer: string;
  model: string;
  generatedAt: string;
  analysis: PerformanceReport;
}

export const RANGES = ["5m", "15m", "30m", "1h", "6h", "24h", "7d"] as const;
export type RangeKey = (typeof RANGES)[number];

// ---- Network monitoring (internal/netwatch, internal/api/network.go) ----

export type NetStatus = "pending" | "up" | "degraded" | "down" | "blocked";

/** One scheduled check. Timings are null when that step didn't run. */
export interface NetCheck {
  targetId: string;
  timestamp: string;
  status: NetStatus;
  dnsMs: number | null;
  connectMs: number | null;
  tlsMs: number | null;
  ttfbMs: number | null;
  responseMs: number | null;
  httpStatus: number | null;
  certDaysLeft: number | null;
  problem?: string;
}

export interface TargetView {
  id: string;
  name: string;
  target: string;
  status: NetStatus;
  last: NetCheck | null;
  since: string | null;
  consecutiveFailures: number;
  checking: boolean;
  nextCheckAt: string;
  recent: NetCheck[];
  uptime24h: number | null;
  checks24h: number;
}

export interface TargetsResponse {
  targets: TargetView[];
  allowPrivateTargets: boolean;
  checkIntervalSeconds: number;
  maxTargets: number;
  historyAvailable: boolean;
  historyError?: string;
}

export interface NetCheckPoint {
  timestamp: string;
  checks: number;
  up: number;
  degraded: number;
  down: number;
  avgResponseMs: number | null;
  maxResponseMs: number | null;
}

export interface NetUptime {
  checks: number;
  up: number;
  degraded: number;
  down: number;
}

export interface TargetHistoryResponse {
  id: string;
  range: string;
  bucketSeconds: number;
  points: NetCheckPoint[];
  uptime: NetUptime;
  uptimePercent: number | null;
}

export const CHECK_KEYS = ["dns", "ports", "tcp", "tls", "http"] as const;
export type CheckKey = (typeof CHECK_KEYS)[number];

export interface ScanRequest {
  target: string;
  checks: CheckKey[];
  ports?: string;
}

// The diagnostics report keeps the engine's snake_case JSON (internal/result),
// the same document `netpulse scan -json` prints. Durations are milliseconds.

export type ProbeStatus = "ok" | "open" | "closed" | "timeout" | "error" | "skipped";

export interface ProbeError {
  kind: string;
  message: string;
}

export interface ReportTarget {
  raw: string;
  host: string;
  port?: number;
  scheme?: string;
  path?: string;
  is_ip: boolean;
}

export interface DNSResult {
  host: string;
  status: ProbeStatus;
  addresses?: string[];
  primary?: string;
  cname?: string;
  literal?: boolean;
  duration_ms: number;
  error?: ProbeError;
}

export interface PortResult {
  port: number;
  service?: string;
  status: ProbeStatus;
  duration_ms: number;
  error?: ProbeError;
}

export interface PortScanResult {
  host: string;
  address?: string;
  scanned: number;
  open: number;
  duration_ms: number;
  results?: PortResult[];
}

export interface TCPResult {
  address: string;
  status: ProbeStatus;
  duration_ms: number;
  local_addr?: string;
  remote_addr?: string;
  error?: ProbeError;
}

export interface Certificate {
  subject: string;
  issuer: string;
  common_name?: string;
  dns_names?: string[];
  not_before: string;
  not_after: string;
  days_until_expiry: number;
  expired: boolean;
  not_yet_valid?: boolean;
  self_signed?: boolean;
  is_ca?: boolean;
}

export interface TLSResult {
  address: string;
  server_name?: string;
  status: ProbeStatus;
  handshake_duration_ms: number;
  version?: string;
  cipher_suite?: string;
  alpn?: string;
  verified: boolean;
  certificates?: Certificate[];
  verify_error?: ProbeError;
  error?: ProbeError;
}

export interface Redirect {
  from?: string;
  to: string;
  status_code?: number;
}

export interface HTTPResult {
  url: string;
  method: string;
  status: ProbeStatus;
  final_url?: string;
  status_code?: number;
  status_text?: string;
  proto?: string;
  ttfb_ms: number;
  duration_ms: number;
  headers?: Record<string, string>;
  redirects?: Redirect[];
  error?: ProbeError;
}

export interface ScanReport {
  target: ReportTarget;
  started_at: string;
  duration_ms: number;
  dns?: DNSResult;
  ports?: PortScanResult;
  tcp?: TCPResult;
  tls?: TLSResult;
  http?: HTTPResult;
  notes?: string[];
}

export interface ScanResponse {
  report: ScanReport;
}
