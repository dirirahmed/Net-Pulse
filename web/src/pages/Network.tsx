import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Sparkline, TimeSeriesChart } from "../components/charts";
import { IconRefresh } from "../components/icons";
import { RangeSelector } from "../components/RangeSelector";
import { Banner, EmptyState, KeyValue, Panel, StatusPill } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { formatRelative } from "../lib/format";
import {
  CHECK_LABELS,
  certStatus,
  formatMs,
  formatUptime,
  historySeries,
  MAX_TARGET_CHARS,
  netStatusLabel,
  netStatusTone,
  probeTone,
  responseSpark,
  scanVerdict,
  sortPorts,
  uptimeTone,
  validateTarget,
} from "../lib/network";
import type { Tone } from "../lib/status";
import { ApiError, api } from "../services/api";
import {
  CHECK_KEYS,
  type CheckKey,
  type NetworkConfig,
  type ProbeStatus,
  type RangeKey,
  type ScanReport,
  type TargetView,
} from "../types/api";

// Targets change at most once per check interval (15 s minimum), so a 5 s
// poll keeps the table fresh without load.
const POLL_MS = 5000;
const HISTORY_POLL_MS = 30_000;
const RECENT_ROWS = 10;

export function Network({ readOnly = false }: { readOnly?: boolean }) {
  const fetcher = useCallback(() => api.targets(), []);
  const { data, error, refresh } = usePolling(fetcher, POLL_MS);
  const [selected, setSelected] = useState<string | null>(null);
  const [netCfg, setNetCfg] = useState<NetworkConfig | null>(null);

  useEffect(() => {
    api
      .settings()
      .then((r) => setNetCfg(r.config.network))
      .catch(() => {
        /* certificate colouring falls back to the defaults below */
      });
  }, []);

  const targets = data?.targets ?? [];
  const current = targets.find((t) => t.id === selected) ?? targets[0];
  const warnDays = netCfg?.certExpiry.warningDays ?? 21;
  const critDays = netCfg?.certExpiry.criticalDays ?? 7;
  const full = data ? targets.length >= data.maxTargets : false;

  return (
    <div className="page network">
      {error && <Banner tone="warning">{error}</Banner>}
      {data && !data.historyAvailable && (
        <Banner tone="warning">Uptime and history are unavailable: {data.historyError}. Live status still works.</Banner>
      )}

      <Panel
        title="Monitored targets"
        aside={
          data && (
            <span className="muted small num">
              {targets.length} of {data.maxTargets} · checked every {data.checkIntervalSeconds} s
            </span>
          )
        }
      >
        {readOnly ? (
          <p className="muted small">
            The demo's targets are fixed. They include a closed port and an expired certificate on purpose, to show outages and alerts.
          </p>
        ) : (
          <AddTarget
            disabled={full}
            allowPrivate={data?.allowPrivateTargets ?? false}
            onAdded={(t) => {
              setSelected(t.id);
              refresh();
            }}
          />
        )}
        {!data ? (
          !error && <p className="muted">Loading targets…</p>
        ) : targets.length === 0 ? (
          <EmptyState>
            No targets yet. Add a website, an API health URL or a host:port above and Net-Pulse checks it on a schedule, keeps its history
            and alerts when it goes down, slows down or its certificate is about to expire.
          </EmptyState>
        ) : (
          <TargetTable
            targets={targets}
            selected={current?.id}
            onSelect={setSelected}
            onChanged={refresh}
            warnDays={warnDays}
            critDays={critDays}
            readOnly={readOnly}
          />
        )}
      </Panel>

      {current && <TargetDetail key={current.id} target={current} warnDays={warnDays} critDays={critDays} />}

      <ScanPanel allowPrivate={data?.allowPrivateTargets ?? false} onMonitored={refresh} readOnly={readOnly} />
    </div>
  );
}

function PrivateHint({ allowPrivate, demo = false }: { allowPrivate: boolean; demo?: boolean }) {
  if (allowPrivate) return null;
  if (demo) return <span className="muted small">Loopback and private network addresses are blocked in the live demo.</span>;
  return (
    <span className="muted small">
      Loopback and LAN addresses are blocked. <a href="#/settings">Allow private targets</a> to check your router or a local service.
    </span>
  );
}

function AddTarget({ disabled, allowPrivate, onAdded }: { disabled: boolean; allowPrivate: boolean; onAdded: (t: TargetView) => void }) {
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [err, setErr] = useState<{ msg: string; blocked: boolean } | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const problem = validateTarget(target);
    if (problem) {
      setErr({ msg: problem, blocked: false });
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const t = await api.addTarget(name.trim(), target.trim());
      setName("");
      setTarget("");
      onAdded(t);
    } catch (e) {
      setErr({ msg: e instanceof Error ? e.message : String(e), blocked: e instanceof ApiError && e.blocked });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="target-form" onSubmit={submit}>
      <input
        type="text"
        value={target}
        onChange={(e) => {
          setTarget(e.target.value);
          setErr(null);
        }}
        placeholder="https://example.com/health, host:port or IP"
        aria-label="Target to monitor"
        maxLength={MAX_TARGET_CHARS}
        className="grow"
      />
      <input
        type="text"
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="Name (optional)"
        aria-label="Display name"
        maxLength={60}
      />
      <button type="submit" className="btn primary" disabled={disabled || busy || !target.trim()}>
        {busy ? "Adding…" : "Add target"}
      </button>
      <div className="target-form-foot">
        {err ? (
          <span className="tone-text-critical small">
            {err.msg} {err.blocked && <a href="#/settings">Open Settings</a>}
          </span>
        ) : disabled ? (
          <span className="muted small">Target limit reached. Remove one to add another.</span>
        ) : (
          <PrivateHint allowPrivate={allowPrivate} />
        )}
      </div>
    </form>
  );
}

function TargetTable({
  targets,
  selected,
  onSelect,
  onChanged,
  warnDays,
  critDays,
  readOnly,
}: {
  targets: TargetView[];
  selected?: string;
  onSelect: (id: string) => void;
  onChanged: () => void;
  warnDays: number;
  critDays: number;
  readOnly: boolean;
}) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const [rowError, setRowError] = useState<string | null>(null);

  const act = async (fn: () => Promise<unknown>) => {
    setRowError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setRowError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      {rowError && <Banner tone="critical">{rowError}</Banner>}
      <div className="table-wrap">
        <table className="table targets">
          <thead>
            <tr>
              <th>Status</th>
              <th>Target</th>
              <th>Response</th>
              <th className="numeric">Uptime 24h</th>
              <th>Certificate</th>
              <th>Last check</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => {
              const cert = certStatus(t.last?.certDaysLeft, warnDays, critDays);
              const spark = responseSpark(t.recent);
              return (
                <tr
                  key={t.id}
                  className={t.id === selected ? "selected" : ""}
                  onClick={() => onSelect(t.id)}
                  aria-selected={t.id === selected}
                >
                  <td>
                    <StatusPill tone={netStatusTone(t.status)}>{t.checking ? "Checking…" : netStatusLabel[t.status]}</StatusPill>
                  </td>
                  <td className="target-cell">
                    <div className="target-name">{t.name}</div>
                    <div className="target-addr mono" title={t.target}>
                      {t.target}
                    </div>
                  </td>
                  <td>
                    <div className="response-cell">
                      <span className="num">{formatMs(t.last?.responseMs)}</span>
                      {spark.length > 1 && <Sparkline values={spark} color="var(--cat-1)" label={`${t.name} response times`} />}
                    </div>
                  </td>
                  <td className={`numeric num tone-text-${uptimeTone(t.uptime24h)}`} title={`${t.checks24h} checks`}>
                    {formatUptime(t.uptime24h)}
                  </td>
                  <td className={`num tone-text-${cert.tone}`}>{cert.text}</td>
                  <td className="num nowrap muted" title={t.last ? new Date(t.last.timestamp).toLocaleString() : undefined}>
                    {t.last ? formatRelative(t.last.timestamp) : "—"}
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div className="row-actions">
                      <button
                        type="button"
                        className="btn small-btn btn-icon"
                        disabled={t.checking}
                        onClick={() => act(() => api.checkNow(t.id))}
                        title="Run the next check now"
                      >
                        <IconRefresh />
                        Check
                      </button>
                      {readOnly ? null : confirming === t.id ? (
                        <button
                          type="button"
                          className="btn small-btn danger"
                          onClick={() => {
                            setConfirming(null);
                            act(() => api.deleteTarget(t.id));
                          }}
                          onBlur={() => setConfirming(null)}
                          autoFocus
                        >
                          Confirm remove
                        </button>
                      ) : (
                        <button type="button" className="btn small-btn" onClick={() => setConfirming(t.id)}>
                          Remove
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function TargetDetail({ target: t, warnDays, critDays }: { target: TargetView; warnDays: number; critDays: number }) {
  const [range, setRange] = useState<RangeKey>("24h");
  const fetcher = useCallback(() => api.targetHistory(t.id, range), [t.id, range]);
  const history = usePolling(fetcher, HISTORY_POLL_MS, `${t.id}:${range}`);
  const series = history.data ? historySeries(history.data.points) : null;
  const gap = history.data ? history.data.bucketSeconds * 1000 * 2.5 : undefined;
  const last = t.last;
  const cert = certStatus(last?.certDaysLeft, warnDays, critDays);
  const recent = [...t.recent].reverse().slice(0, RECENT_ROWS);

  return (
    <Panel
      title={t.name}
      aside={
        <span className="panel-aside-row">
          {history.data?.uptimePercent != null && (
            <span className={`small num tone-text-${uptimeTone(history.data.uptimePercent)}`}>
              {formatUptime(history.data.uptimePercent)} uptime ({range})
            </span>
          )}
          <RangeSelector value={range} onChange={setRange} />
        </span>
      }
    >
      {last && last.status !== "up" && last.problem && (
        <Banner tone={netStatusTone(last.status)}>
          {last.problem}
          {t.consecutiveFailures > 1 && ` (${t.consecutiveFailures} checks in a row)`}
        </Banner>
      )}
      <div className="target-detail">
        <KeyValue
          items={[
            ["Status", <StatusPill tone={netStatusTone(t.status)}>{netStatusLabel[t.status]}</StatusPill>],
            ["Since", t.since ? `${new Date(t.since).toLocaleString()} (${formatRelative(t.since)})` : "—"],
            ["DNS lookup", formatMs(last?.dnsMs)],
            ["TCP connect", formatMs(last?.connectMs)],
            ["TLS handshake", formatMs(last?.tlsMs)],
            ["Time to first byte", formatMs(last?.ttfbMs)],
            ["Response time", formatMs(last?.responseMs)],
            ["HTTP status", last?.httpStatus ?? "—"],
            ["Certificate", <span className={`tone-text-${cert.tone}`}>{cert.text}</span>],
            ["Next check", t.checking ? "running now" : new Date(t.nextCheckAt).toLocaleTimeString()],
          ]}
        />
        <div className="target-charts">
          {history.error && <p className="muted small">{history.error}</p>}
          {series && (
            <>
              <h3 className="chart-title">Response time</h3>
              <TimeSeriesChart
                times={series.times}
                series={[
                  { key: "avg", label: "Average", color: "var(--cat-1)", values: series.avg },
                  { key: "peak", label: "Peak", color: "var(--cat-2)", values: series.peak },
                ]}
                format={formatMs}
                axisFormat={(v) => formatMs(v)}
                height={170}
                maxGapMs={gap}
                emptyText="No successful checks in this range"
              />
              <h3 className="chart-title">Availability</h3>
              <TimeSeriesChart
                times={series.times}
                series={[{ key: "avail", label: "Checks that reached the target", color: "var(--cat-3)", values: series.availability }]}
                format={(v) => (v == null ? "—" : `${Math.round(v)}%`)}
                axisFormat={(v) => `${v}%`}
                yMax={100}
                height={120}
                maxGapMs={gap}
                showLegend={false}
              />
            </>
          )}
        </div>
      </div>

      <h3 className="chart-title">Recent checks</h3>
      {recent.length === 0 ? (
        <EmptyState>The first check runs within a few seconds of adding a target.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Status</th>
                <th className="numeric">Response</th>
                <th className="numeric">HTTP</th>
                <th>Problem</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((c, i) => (
                <tr key={`${c.timestamp}-${i}`}>
                  <td className="num nowrap">{new Date(c.timestamp).toLocaleTimeString()}</td>
                  <td>
                    <StatusPill tone={netStatusTone(c.status)}>{netStatusLabel[c.status]}</StatusPill>
                  </td>
                  <td className="numeric num">{formatMs(c.responseMs)}</td>
                  <td className="numeric num">{c.httpStatus ?? "—"}</td>
                  <td className="reason">{c.problem ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

const DEFAULT_CHECKS: Record<CheckKey, boolean> = { dns: true, ports: false, tcp: true, tls: true, http: true };

function ScanPanel({ allowPrivate, onMonitored, readOnly }: { allowPrivate: boolean; onMonitored: () => void; readOnly: boolean }) {
  const [target, setTarget] = useState("");
  const [checks, setChecks] = useState(DEFAULT_CHECKS);
  const [ports, setPorts] = useState("default");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ msg: string; blocked: boolean } | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [monitorMsg, setMonitorMsg] = useState<string | null>(null);

  const selected = CHECK_KEYS.filter((k) => checks[k]);

  const run = async (e: FormEvent) => {
    e.preventDefault();
    const problem = validateTarget(target) ?? (selected.length === 0 ? "Pick at least one check." : null);
    if (problem) {
      setErr({ msg: problem, blocked: false });
      return;
    }
    setBusy(true);
    setErr(null);
    setMonitorMsg(null);
    try {
      const r = await api.scan({ target: target.trim(), checks: selected, ports: checks.ports ? ports : undefined });
      setReport(r.report);
    } catch (e) {
      setErr({ msg: e instanceof Error ? e.message : String(e), blocked: e instanceof ApiError && e.blocked });
    } finally {
      setBusy(false);
    }
  };

  const monitor = async () => {
    if (!report) return;
    try {
      const t = await api.addTarget("", report.target.raw);
      setMonitorMsg(`Now monitoring ${t.name}.`);
      onMonitored();
    } catch (e) {
      setMonitorMsg(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <Panel
      title="Diagnostics"
      aside={
        <span className="muted small">
          Runs once: the same checks as <code>netpulse scan</code>
        </span>
      }
    >
      <form className="scan-form" onSubmit={run}>
        <div className="target-form">
          <input
            type="text"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              setErr(null);
            }}
            placeholder="example.com, 1.1.1.1:53 or https://example.com/health"
            aria-label="Target to scan"
            maxLength={MAX_TARGET_CHARS}
            className="grow"
          />
          <button type="submit" className="btn primary" disabled={busy || !target.trim()}>
            {busy ? "Scanning…" : "Run scan"}
          </button>
        </div>
        <div className="scan-options">
          <div className="chips" role="group" aria-label="Checks to run">
            {CHECK_KEYS.map((k) => (
              <button
                key={k}
                type="button"
                className={`chip ${checks[k] ? "on" : ""}`}
                aria-pressed={checks[k]}
                onClick={() => setChecks({ ...checks, [k]: !checks[k] })}
              >
                {CHECK_LABELS[k]}
              </button>
            ))}
          </div>
          {checks.ports && (
            <label className="select small">
              Ports
              <input
                type="text"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                aria-label="Ports to scan"
                className="ports-input"
              />
              <span className="muted">default, or a list like 22,80,443,8000-8010 (max 1024)</span>
            </label>
          )}
        </div>
        <div className="target-form-foot">
          {err ? (
            <span className="tone-text-critical small">
              {err.msg} {err.blocked && !readOnly && <a href="#/settings">Open Settings</a>}
            </span>
          ) : (
            <PrivateHint allowPrivate={allowPrivate} demo={readOnly} />
          )}
        </div>
      </form>

      {busy && <p className="muted">Running checks… a port scan or a slow server can take up to a minute.</p>}
      {report && !busy && (
        <ScanResult
          report={report}
          action={
            !readOnly && (
              <span className="panel-aside-row">
                {monitorMsg && <span className="small muted">{monitorMsg}</span>}
                <button type="button" className="btn small-btn" onClick={monitor} disabled={monitorMsg?.startsWith("Now monitoring")}>
                  Monitor this target
                </button>
              </span>
            )
          }
        />
      )}
    </Panel>
  );
}

interface StepStatus {
  tone: Tone;
  label: string;
}

const stepStatus = (s: ProbeStatus): StepStatus => ({ tone: probeTone(s), label: s });

function Step({ title, status, duration, children }: { title: string; status?: StepStatus; duration?: number; children: ReactNode }) {
  return (
    <section className="scan-step">
      <header>
        <h3>{title}</h3>
        <span className="panel-aside-row">
          {duration != null && <span className="num small muted">{formatMs(duration)}</span>}
          {status && <StatusPill tone={status.tone}>{status.label}</StatusPill>}
        </span>
      </header>
      {children}
    </section>
  );
}

export function ScanResult({ report: r, action }: { report: ScanReport; action?: ReactNode }) {
  const [showClosed, setShowClosed] = useState(false);
  const verdict = scanVerdict(r);
  const leaf = r.tls?.certificates?.[0];
  const ports = sortPorts(r.ports?.results, showClosed);

  return (
    <div className="scan-result">
      <div className="scan-head">
        <StatusPill tone={verdict.tone}>{verdict.text}</StatusPill>
        <span className="muted small num">
          {r.target.raw} · {formatMs(r.duration_ms)}
        </span>
        <span className="grow" />
        {action}
      </div>

      <div className="scan-steps">
        {r.dns && (
          <Step title="DNS" status={stepStatus(r.dns.status)} duration={r.dns.literal ? undefined : r.dns.duration_ms}>
            <KeyValue
              items={[
                ["Addresses", r.dns.literal ? "IP literal, no lookup needed" : r.dns.addresses?.join(", ") || "—"],
                ...(r.dns.cname ? ([["CNAME", r.dns.cname]] as [string, ReactNode][]) : []),
                ...(r.dns.error ? ([["Error", r.dns.error.message]] as [string, ReactNode][]) : []),
              ]}
            />
          </Step>
        )}
        {r.tcp && (
          <Step title="TCP" status={stepStatus(r.tcp.status)} duration={r.tcp.duration_ms}>
            <KeyValue
              items={[
                ["Address", <span className="mono">{r.tcp.address}</span>],
                ...(r.tcp.error ? ([["Error", r.tcp.error.message]] as [string, ReactNode][]) : []),
              ]}
            />
          </Step>
        )}
        {r.tls && (
          <Step
            title="TLS"
            status={r.tls.verify_error ? { tone: "warning", label: "not verified" } : stepStatus(r.tls.status)}
            duration={r.tls.handshake_duration_ms}
          >
            <KeyValue
              items={[
                ["Verified", r.tls.verified ? "Yes" : <span className="tone-text-critical">No</span>],
                ["Version", r.tls.version ? `${r.tls.version} · ${r.tls.cipher_suite ?? ""}` : "—"],
                ...(r.tls.alpn ? ([["ALPN", r.tls.alpn]] as [string, ReactNode][]) : []),
                ...(leaf
                  ? ([
                      ["Subject", leaf.subject],
                      ["Issuer", leaf.issuer],
                      ["Names", leaf.dns_names?.join(", ") || "—"],
                      [
                        "Expires",
                        <span className={leaf.expired ? "tone-text-critical" : undefined}>
                          {new Date(leaf.not_after).toLocaleDateString()} (
                          {leaf.expired ? `expired ${-leaf.days_until_expiry} days ago` : `in ${leaf.days_until_expiry} days`})
                        </span>,
                      ],
                    ] as [string, ReactNode][])
                  : []),
                ...((r.tls.verify_error ?? r.tls.error)
                  ? ([["Error", (r.tls.verify_error ?? r.tls.error)!.message]] as [string, ReactNode][])
                  : []),
              ]}
            />
          </Step>
        )}
        {r.http && (
          <Step title="HTTP" status={stepStatus(r.http.status)} duration={r.http.duration_ms}>
            <KeyValue
              items={[
                ["Response", r.http.status_code ? `${r.http.status_code} ${r.http.proto ?? ""}` : "—"],
                ["First byte", formatMs(r.http.ttfb_ms)],
                ["URL", <span className="mono break">{r.http.url}</span>],
                ...(r.http.final_url && r.http.final_url !== r.http.url
                  ? ([["Final URL", <span className="mono break">{r.http.final_url}</span>]] as [string, ReactNode][])
                  : []),
                ...(r.http.redirects?.length
                  ? ([["Redirects", `${r.http.redirects.length} (${r.http.redirects.map((x) => x.status_code).join(" → ")})`]] as [
                      string,
                      ReactNode,
                    ][])
                  : []),
                ...(["Server", "Content-Type", "Strict-Transport-Security"]
                  .filter((h) => r.http?.headers?.[h])
                  .map((h) => [h, <span className="mono break">{r.http!.headers![h]}</span>]) as [string, ReactNode][]),
                ...(r.http.error ? ([["Error", r.http.error.message]] as [string, ReactNode][]) : []),
              ]}
            />
          </Step>
        )}
      </div>

      {r.ports && (
        <Step title={`Ports · ${r.ports.open} of ${r.ports.scanned} open`} duration={r.ports.duration_ms}>
          <label className="small muted check-inline">
            <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Show closed and filtered ports
          </label>
          {ports.length === 0 ? (
            <EmptyState>No open ports among the ones scanned.</EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th className="numeric">Port</th>
                    <th>Service</th>
                    <th>Status</th>
                    <th className="numeric">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {ports.map((p) => (
                    <tr key={p.port}>
                      <td className="numeric num">{p.port}</td>
                      <td>{p.service || <span className="muted">unknown</span>}</td>
                      <td>
                        <StatusPill tone={probeTone(p.status)}>{p.status}</StatusPill>
                      </td>
                      <td className="numeric num">{formatMs(p.duration_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Step>
      )}

      {r.notes && r.notes.length > 0 && (
        <ul className="analysis-notes">
          {r.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
