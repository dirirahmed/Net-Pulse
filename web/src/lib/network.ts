import type { Tone } from "./status";
import type { CheckKey, NetCheck, NetCheckPoint, NetStatus, PortResult, ProbeStatus, ScanReport } from "../types/api";

export const netStatusLabel: Record<NetStatus, string> = {
  pending: "Pending",
  up: "Up",
  degraded: "Degraded",
  down: "Down",
  blocked: "Blocked",
};

export function netStatusTone(s: NetStatus): Tone {
  switch (s) {
    case "up":
      return "good";
    case "degraded":
      return "warning";
    case "down":
      return "critical";
    default:
      return "muted";
  }
}

/** Tone for one diagnostics step in a scan report. */
export function probeTone(s: ProbeStatus | undefined): Tone {
  switch (s) {
    case "ok":
    case "open":
      return "good";
    case "timeout":
      return "warning";
    case "error":
      return "critical";
    default:
      return "muted";
  }
}

/** Step durations. A step that didn't run shows a dash, not "0 ms". */
export function formatMs(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v)) return "—";
  if (v < 1) return "<1 ms";
  if (v < 1000) return `${Math.round(v)} ms`;
  return `${(v / 1000).toFixed(v < 10_000 ? 2 : 1)} s`;
}

/** 100 → "100%", 99.95 → "99.95%", 97.333 → "97.3%". */
export function formatUptime(p: number | null | undefined): string {
  if (p == null || !Number.isFinite(p)) return "—";
  if (p >= 100) return "100%";
  if (p >= 99) return `${(Math.floor(p * 100) / 100).toFixed(2)}%`;
  return `${(Math.floor(p * 10) / 10).toFixed(1)}%`;
}

export function uptimeTone(p: number | null | undefined): Tone {
  if (p == null) return "muted";
  if (p >= 99) return "good";
  if (p >= 95) return "warning";
  return "critical";
}

/** Certificate days left against the configured warning/critical days. */
export function certStatus(days: number | null | undefined, warningDays: number, criticalDays: number): { text: string; tone: Tone } {
  if (days == null) return { text: "—", tone: "muted" };
  if (days < 0) return { text: `Expired ${-days} d ago`, tone: "critical" };
  const text = days === 1 ? "1 day" : `${days} days`;
  if (days <= criticalDays) return { text, tone: "critical" };
  if (days <= warningDays) return { text, tone: "warning" };
  return { text, tone: "good" };
}

/** Response times of recent checks for a sparkline; failed checks are gaps. */
export function responseSpark(recent: NetCheck[]): (number | null)[] {
  return recent.map((c) => (c.status === "down" || c.status === "blocked" ? null : c.responseMs));
}

export interface HistorySeries {
  times: number[];
  avg: (number | null)[];
  peak: (number | null)[];
  /** Share of checks in each bucket that reached the target, 0-100. */
  availability: (number | null)[];
}

export function historySeries(points: NetCheckPoint[]): HistorySeries {
  const out: HistorySeries = { times: [], avg: [], peak: [], availability: [] };
  for (const p of points) {
    out.times.push(Date.parse(p.timestamp));
    out.avg.push(p.avgResponseMs);
    out.peak.push(p.maxResponseMs);
    out.availability.push(p.checks > 0 ? ((p.up + p.degraded) / p.checks) * 100 : null);
  }
  return out;
}

export const CHECK_LABELS: Record<CheckKey, string> = {
  dns: "DNS",
  ports: "Ports",
  tcp: "TCP",
  tls: "TLS",
  http: "HTTP",
};

export const MAX_TARGET_CHARS = 300;

/** Light client-side checks; the agent validates properly. */
export function validateTarget(raw: string): string | null {
  const s = raw.trim();
  if (!s) return "Enter a hostname, IP address or URL.";
  if (s.length > MAX_TARGET_CHARS) return `Keep it under ${MAX_TARGET_CHARS} characters.`;
  if (/\s/.test(s)) return "A target can't contain spaces.";
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(s);
  if (scheme && !["http", "https"].includes(scheme[1].toLowerCase())) return "Only http:// and https:// URLs are supported.";
  return null;
}

/** Open ports first, then everything else by port number. */
export function sortPorts(results: PortResult[] | undefined, showClosed: boolean): PortResult[] {
  const list = (results ?? []).filter((r) => showClosed || r.status === "open");
  return [...list].sort((a, b) => Number(b.status === "open") - Number(a.status === "open") || a.port - b.port);
}

/** One-line verdict for a scan, mirroring how scheduled checks are judged. */
export function scanVerdict(r: ScanReport): { tone: Tone; text: string } {
  if (r.dns && r.dns.status !== "ok") return { tone: "critical", text: "The name did not resolve." };
  if (r.tcp && r.tcp.status !== "ok") return { tone: "critical", text: `Could not connect to ${r.tcp.address}.` };
  if (r.tls && r.tls.status !== "ok") {
    return r.tls.verify_error
      ? { tone: "warning", text: "Reachable, but the TLS certificate does not validate." }
      : { tone: "critical", text: "The TLS handshake failed." };
  }
  if (r.http) {
    if (r.http.status !== "ok") return { tone: "critical", text: "The HTTP request failed." };
    const code = r.http.status_code ?? 0;
    if (code >= 500) return { tone: "warning", text: `Reachable, but the server answered ${code}.` };
  }
  if (r.ports && !r.dns && !r.tcp && !r.tls && !r.http) {
    return { tone: r.ports.open > 0 ? "good" : "muted", text: `${r.ports.open} of ${r.ports.scanned} ports open.` };
  }
  return { tone: "good", text: "Everything that ran succeeded." };
}
