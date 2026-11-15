import type {
  AlertsResponse,
  AnalysisResponse,
  AskResponse,
  ChatTurn,
  Config,
  MetricsResponse,
  ProcessesResponse,
  RangeKey,
  ScanRequest,
  ScanResponse,
  SettingsResponse,
  SystemResponse,
  TargetHistoryResponse,
  TargetView,
  TargetsResponse,
} from "../types/api";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    /** The target was refused by the private-address guard. */
    readonly blocked = false,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

const TIMEOUT_MS = 10_000;
const JSON_HEADERS = { "Content-Type": "application/json" };
// AI answers come from a remote model and can take much longer than telemetry.
const AI_TIMEOUT_MS = 100_000;
// The agent caps a scan at 60 s; leave room for the response.
const SCAN_TIMEOUT_MS = 75_000;

async function request<T>(path: string, init?: RequestInit, timeoutMs = TIMEOUT_MS): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(path, { ...init, signal: controller.signal });
  } catch (err) {
    const aborted = err instanceof DOMException && err.name === "AbortError";
    throw new ApiError(aborted ? "Request timed out" : "Cannot reach the Net-Pulse agent", 0);
  } finally {
    clearTimeout(timer);
  }
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const msg = body && typeof body.error === "string" ? body.error : `HTTP ${res.status}`;
    throw new ApiError(msg, res.status, body?.blocked === true);
  }
  return body as T;
}

export const api = {
  system: () => request<SystemResponse>("/api/system"),
  metrics: (range: RangeKey, withDisks = false) => request<MetricsResponse>(`/api/metrics?range=${range}${withDisks ? "&disks=1" : ""}`),
  processes: () => request<ProcessesResponse>("/api/processes"),
  alerts: (limit = 200) => request<AlertsResponse>(`/api/alerts?limit=${limit}`),
  settings: () => request<SettingsResponse>("/api/settings"),
  saveSettings: (config: Config) =>
    request<SettingsResponse>("/api/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    }),
  analysis: () => request<AnalysisResponse>("/api/analysis"),
  ask: (question: string, history: ChatTurn[]) =>
    request<AskResponse>(
      "/api/ai/ask",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, history }),
      },
      AI_TIMEOUT_MS,
    ),
  targets: () => request<TargetsResponse>("/api/targets"),
  addTarget: (name: string, target: string) =>
    request<TargetView>("/api/targets", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ name, target }) }),
  deleteTarget: (id: string) => request<void>(`/api/targets/${encodeURIComponent(id)}`, { method: "DELETE" }),
  checkNow: (id: string) =>
    request<{ status: string }>(`/api/targets/${encodeURIComponent(id)}/check`, { method: "POST", headers: JSON_HEADERS, body: "{}" }),
  targetHistory: (id: string, range: RangeKey) =>
    request<TargetHistoryResponse>(`/api/targets/${encodeURIComponent(id)}/history?range=${range}`),
  scan: (req: ScanRequest) =>
    request<ScanResponse>("/api/scan", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify(req) }, SCAN_TIMEOUT_MS),
};
