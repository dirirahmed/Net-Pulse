import { describe, expect, it } from "vitest";
import {
  certStatus,
  formatMs,
  formatUptime,
  historySeries,
  netStatusTone,
  responseSpark,
  scanVerdict,
  sortPorts,
  uptimeTone,
  validateTarget,
} from "./network";
import type { NetCheck, ScanReport } from "../types/api";

const check = (status: NetCheck["status"], responseMs: number | null): NetCheck => ({
  targetId: "t",
  timestamp: "2026-11-15T00:00:00Z",
  status,
  dnsMs: null,
  connectMs: null,
  tlsMs: null,
  ttfbMs: null,
  responseMs,
  httpStatus: null,
  certDaysLeft: null,
});

describe("formatting", () => {
  it("formats step durations", () => {
    expect(formatMs(null)).toBe("—");
    expect(formatMs(0.4)).toBe("<1 ms");
    expect(formatMs(123.6)).toBe("124 ms");
    expect(formatMs(1534)).toBe("1.53 s");
    expect(formatMs(12_340)).toBe("12.3 s");
  });

  it("never rounds uptime up to 100%", () => {
    expect(formatUptime(null)).toBe("—");
    expect(formatUptime(100)).toBe("100%");
    expect(formatUptime(99.999)).toBe("99.99%");
    expect(formatUptime(97.38)).toBe("97.3%");
    expect(uptimeTone(99.5)).toBe("good");
    expect(uptimeTone(96)).toBe("warning");
    expect(uptimeTone(80)).toBe("critical");
    expect(uptimeTone(null)).toBe("muted");
  });

  it("maps statuses to tones", () => {
    expect(netStatusTone("up")).toBe("good");
    expect(netStatusTone("degraded")).toBe("warning");
    expect(netStatusTone("down")).toBe("critical");
    expect(netStatusTone("blocked")).toBe("muted");
  });
});

describe("certStatus", () => {
  it("uses the configured thresholds", () => {
    expect(certStatus(null, 21, 7)).toEqual({ text: "—", tone: "muted" });
    expect(certStatus(60, 21, 7).tone).toBe("good");
    expect(certStatus(21, 21, 7).tone).toBe("warning");
    expect(certStatus(7, 21, 7).tone).toBe("critical");
    expect(certStatus(1, 21, 7).text).toBe("1 day");
    expect(certStatus(-3, 21, 7)).toEqual({ text: "Expired 3 d ago", tone: "critical" });
  });
});

describe("series", () => {
  it("leaves gaps for failed checks", () => {
    expect(responseSpark([check("up", 10), check("down", null), check("degraded", 900), check("blocked", null)])).toEqual([
      10,
      null,
      900,
      null,
    ]);
  });

  it("computes availability per bucket", () => {
    const s = historySeries([
      { timestamp: "2026-11-15T00:00:00Z", checks: 4, up: 2, degraded: 1, down: 1, avgResponseMs: 50, maxResponseMs: 90 },
      { timestamp: "2026-11-15T00:05:00Z", checks: 0, up: 0, degraded: 0, down: 0, avgResponseMs: null, maxResponseMs: null },
    ]);
    expect(s.availability).toEqual([75, null]);
    expect(s.avg).toEqual([50, null]);
    expect(s.times[1] - s.times[0]).toBe(300_000);
  });
});

describe("validateTarget", () => {
  it("accepts what the CLI accepts and catches obvious mistakes", () => {
    for (const ok of ["example.com", "1.1.1.1:53", "[::1]:443", "https://example.com/health", "HTTP://x.io"]) {
      expect(validateTarget(ok)).toBeNull();
    }
    expect(validateTarget("  ")).toMatch(/Enter/);
    expect(validateTarget("my host")).toMatch(/spaces/);
    expect(validateTarget("ftp://x.io")).toMatch(/http/);
    expect(validateTarget("a".repeat(301))).toMatch(/300/);
  });
});

describe("scan helpers", () => {
  const base: ScanReport = { target: { raw: "x", host: "x", is_ip: false }, started_at: "", duration_ms: 10 };

  it("sorts open ports first and hides closed ones by default", () => {
    const ports = [
      { port: 443, status: "open" as const, duration_ms: 1 },
      { port: 22, status: "closed" as const, duration_ms: 1 },
      { port: 80, status: "open" as const, duration_ms: 1 },
    ];
    expect(sortPorts(ports, false).map((p) => p.port)).toEqual([80, 443]);
    expect(sortPorts(ports, true).map((p) => p.port)).toEqual([80, 443, 22]);
    expect(sortPorts(undefined, true)).toEqual([]);
  });

  it("judges a report like a scheduled check", () => {
    expect(scanVerdict({ ...base, dns: { host: "x", status: "error", duration_ms: 1 } }).tone).toBe("critical");
    expect(scanVerdict({ ...base, tcp: { address: "x:443", status: "timeout", duration_ms: 1 } }).text).toMatch(/x:443/);
    const badCert = {
      address: "x",
      status: "error" as const,
      handshake_duration_ms: 1,
      verified: false,
      verify_error: { kind: "certificate", message: "expired" },
    };
    expect(scanVerdict({ ...base, tls: badCert }).tone).toBe("warning");
    const http = (code: number) => ({ url: "u", method: "GET", status: "ok" as const, status_code: code, ttfb_ms: 1, duration_ms: 1 });
    expect(scanVerdict({ ...base, http: http(503) }).tone).toBe("warning");
    expect(scanVerdict({ ...base, http: http(404) }).tone).toBe("good");
    expect(scanVerdict({ ...base, ports: { host: "x", scanned: 12, open: 2, duration_ms: 1 } }).text).toBe("2 of 12 ports open.");
  });
});
