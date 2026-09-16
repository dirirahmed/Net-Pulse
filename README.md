# Net-Pulse

A concurrent TCP port scanner written in Go. Give it a target and a port
range, it dials every port with a bounded worker pool and tells you which
ones accepted a TCP connection, how long the connect took, and why the
ones that failed, failed.

This is V1. It only does TCP connect scanning - no HTTP probing, no TLS,
no protocol validation, no fancy output formats. See [V2 roadmap](#v2-roadmap)
for what's next.

## What V1 actually does

- Parses port specs: single ports, comma lists, ranges, or a mix
  (`22,80,443,8000-8100`)
- Resolves the target once (prefers IPv4), not once per port
- Scans through a bounded worker pool (default 100 workers, configurable
  1-5000)
- Classifies every result: `OPEN`, `CLOSED`, `TIMEOUT`, or `ERROR`, with a
  specific error type when it's not open
- Measures TCP connect latency for open ports
- Hints at a service name based on the port number (from a small built-in
  registry) - **this is a guess, not a verified protocol check**
- Handles Ctrl+C cleanly: stops scheduling new work, prints whatever it
  already found, exits with code 130

That's it. If you want to know whether port 80 is *actually* running HTTP
and not something else squatting on the port, that's V2's job.

## Install / build

Needs Go installed (whatever version `go.mod` currently pins, via
`go mod init`'s default - check `go.mod` for the exact line). No external
dependencies, standard library only.

```bash
git clone https://github.com/dirirahmed/Net-Pulse.git
cd Net-Pulse
go build -o netpulse ./cmd/netpulse
```

Or just run it directly without building a binary:

```bash
go run ./cmd/netpulse scan 127.0.0.1
```

## Usage

```
netpulse scan [flags] <target>
```

Target is required - a hostname or an IP. Flags can go before or after
the target, both work:

```bash
netpulse scan 127.0.0.1
netpulse scan --ports 22,80,443 192.168.1.1
netpulse scan --ports 1-1000 --workers 200 --timeout 500ms 192.168.1.1
netpulse scan --verbose example.com
netpulse scan 192.168.1.1 --ports 1-1000   # flags after target work too
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--ports` | common service registry | ports to scan: `80`, `22,80,443`, `1-1000`, or `22,80,8000-8100` |
| `--workers` | `100` | concurrent workers, must be 1-5000 |
| `--timeout` | `1s` | per-connection dial timeout, must be > 0 |
| `--verbose` | `false` | show non-open results (closed/timeout/error) and the error classification column |

By default (no `--ports`), it scans the built-in service registry ports
(21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080).

### Example output

```
$ netpulse scan --ports 22,80,443,9999 127.0.0.1
netpulse: scanning 127.0.0.1 - 4 ports, 100 workers, 1s timeout
PORT  STATE  SERVICE  LATENCY
80    OPEN   HTTP     1.2ms
443   OPEN   HTTPS    0.9ms

$ netpulse scan --ports 22,80,443,9999 --verbose 127.0.0.1
netpulse: scanning 127.0.0.1 - 4 ports, 100 workers, 1s timeout
PORT  STATE   SERVICE  LATENCY  ERROR
22    CLOSED  SSH      -        CONNECTION_REFUSED
80    OPEN    HTTP     1.2ms    -
443   OPEN    HTTPS    0.9ms    -
9999  CLOSED  unknown  -        CONNECTION_REFUSED
```

Normal output only shows open ports - that's usually all you care about.
`--verbose` shows everything plus why the closed ones are closed.

## Architecture

```
cmd/netpulse/       CLI entry point, flag parsing, signal handling
internal/model/      Result type, State/ErrorType enums
internal/scanner/    port parsing, service registry, TCP probing, worker pool
internal/report/     tabwriter output
```

### Worker pool

```
producer -> jobs channel -> N workers -> results channel -> aggregator
```

One goroutine (the producer) feeds ports into a channel. A fixed number
of worker goroutines pull from that channel, dial the port, and push a
`Result` onto a results channel. A single aggregator goroutine collects
everything and sorts by port before printing.

This isn't one-goroutine-per-port - worker count is capped (default 100,
max 5000), and never exceeds the number of ports being scanned. Both the
producer and every worker select on `ctx.Done()` so a cancelled context
stops the whole pipeline instead of leaking goroutines waiting to send
results nobody's reading anymore.

### DNS resolution

The target gets resolved exactly once, before any port gets touched, and
that resolved address gets reused for every probe. DNS lookup time is
never included in the per-port latency numbers - if it were, latency
would just be measuring your DNS server's response time on the first
probe and near-zero on the rest, which would be meaningless.

## What "latency" means here

It's the wall-clock time from starting the `DialContext` call to it
returning successfully - basically how long the whole TCP handshake +
local scheduling overhead took, measured with `time.Now()` /
`time.Since()`. It is **not** pure network round-trip time. Local
goroutine scheduling, OS socket setup, and Go runtime overhead are all
baked into that number. On loopback it'll often show up as fractions of
a millisecond or even `0s` (yes, a real TCP connect can complete faster
than the clock can measure it).

Latency is only reported for `OPEN` results. Everything else shows `-`.

## Error classification

A closed or errored port gets one of these:

| Error type | Meaning |
|---|---|
| `CONNECTION_REFUSED` | Something actively rejected the connection (RST) - port is closed, host is up |
| `TIMEOUT` | No response within `--timeout` - could be a firewall silently dropping packets, could just be a slow host. **We never call this "filtered"** - we don't know why it didn't respond in time, only that it didn't |
| `NETWORK_UNREACHABLE` | OS couldn't route to the network at all |
| `HOST_UNREACHABLE` | Network was reachable but the specific host wasn't |
| `UNKNOWN` | Anything else - including local resource issues that have nothing to do with the target (see note below) |

Classification uses `errors.Is` against the actual OS error. Worth
knowing: on Windows, `net`'s errors carry raw Winsock codes that don't
match the `syscall.ECONNREFUSED`-style constants Go defines for
POSIX-compat - those constants are never actually returned by the network
stack on Windows. Net-Pulse has separate Windows/non-Windows error
constant files so classification works correctly on both instead of
silently falling back to `UNKNOWN` on Windows.

## Service hints

The port -> service name mapping (`22` -> `SSH`, `443` -> `HTTPS`, etc.)
is a lookup table based on well-known port assignments. **An `OPEN`
result means a TCP connection succeeded on that port - it does not mean
we verified the service actually speaking on that port.** Something could
easily be listening on 443 that isn't HTTPS at all. Confirming that is a
V2 problem (protocol validation / TLS inspection).

## Cancellation (Ctrl+C)

`signal.NotifyContext` catches SIGINT/SIGTERM and cancels the scan's
context. When that happens:

- the producer stops handing out new ports
- workers stop after finishing whatever probe they're mid-flight on
- whatever results already came back get printed
- stderr gets a message saying the scan was interrupted
- exit code is `130`

## Testing

```bash
go test ./...
go test -race ./...
```

Tests cover: port parsing (valid/invalid/edge cases, table-driven),
service hints, TCP probing against real local listeners (open, refused,
timeout via an injected deterministic dialer - not relying on flaky real
network timeouts), error classification, worker pool bounding and
parallelism, result ordering, cancellation, hostname resolution, and
goroutine leak checks (via polling `runtime.NumGoroutine`, no third-party
leak-detection library).

There's a test seam for this: `Config` has an unexported `dial` field
(same shape as `net.Dialer.DialContext`) that tests can swap out for a
fixed-delay fake dialer to get deterministic timing without real sockets.

One thing worth knowing if you run the suite repeatedly in a short window:
the tests and benchmarks open a lot of short-lived local TCP connections.
On a machine with a small ephemeral port range (Windows defaults to
49152-65535), hammering `go test -race -count=N` back to back can
transiently exhaust that range with connections stuck in `TIME_WAIT` and
cause a spurious `WSAEADDRINUSE`-classified failure. It clears itself
within seconds - it's not a scanner bug, just local port pressure from
testing itself hard.

## Benchmarks

```bash
go test -bench=. -benchmem ./...
```

`BenchmarkSequentialScan` probes ports one at a time as a baseline.
`BenchmarkWorkerPoolScan` runs the same ports through the real worker
pool against real local listeners, sub-benchmarked at 1/5/10/25/50/100/250
workers. `BenchmarkWorkerPoolScanSyntheticDelay` does the same sweep but
with an injected fixed-delay dialer instead of real sockets, since
real-socket numbers get noisy from OS scheduling.

Measured on: Windows 11 Pro (build 10.0.26200), AMD Ryzen 5 3600 (6c/12t),
go1.27.0 windows/amd64.

```
goos: windows
goarch: amd64
pkg: github.com/dirirahmed/Net-Pulse/internal/scanner
cpu: AMD Ryzen 5 3600 6-Core Processor
BenchmarkSequentialScan-12                             164   9189897 ns/op    82280 B/op   1320 allocs/op
BenchmarkWorkerPoolScan/workers=1-12                   100  11153951 ns/op    85673 B/op   1331 allocs/op
BenchmarkWorkerPoolScan/workers=5-12                   298   4985076 ns/op    86411 B/op   1339 allocs/op
BenchmarkWorkerPoolScan/workers=10-12                  198   6997303 ns/op    86869 B/op   1345 allocs/op
BenchmarkWorkerPoolScan/workers=25-12                   94  13801184 ns/op    87182 B/op   1341 allocs/op
BenchmarkWorkerPoolScan/workers=50-12                   73  15408758 ns/op    80680 B/op   1240 allocs/op
BenchmarkWorkerPoolScan/workers=100-12                  73  15839971 ns/op    77638 B/op   1209 allocs/op
BenchmarkWorkerPoolScan/workers=250-12                 100  14148697 ns/op    77760 B/op   1209 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=1-12        3 467529900 ns/op  143712 B/op   1911 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=5-12       12  93229133 ns/op  144032 B/op   1915 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=10-12      25  47058280 ns/op  144582 B/op   1921 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=25-12      66  18752982 ns/op  145910 B/op   1937 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=50-12     124   9626912 ns/op  148031 B/op   1962 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=100-12    244   4889929 ns/op  152183 B/op   2014 allocs/op
BenchmarkWorkerPoolScanSyntheticDelay/workers=250-12    458   2651194 ns/op  160376 B/op   2116 allocs/op
```

The synthetic-delay numbers are the clean story: latency per scan drops
almost linearly as worker count goes up, exactly what you'd expect from
a bounded pool doing `numPorts / numWorkers` rounds of a fixed-cost
operation. The real-socket `BenchmarkWorkerPoolScan` numbers are noisier
and don't scale as cleanly - real loopback connects have enough OS
scheduling variance on a small (40-port) sample that the trend gets
buried in noise. That's expected for a real-network micro-benchmark;
the synthetic one exists specifically to see the pool's actual scaling
behavior without that noise.

## Security scope

Net-Pulse does TCP connect scans - it opens a real TCP connection and
closes it. That's it. It does not:

- do anything with what's actually running on an open port
- attempt any kind of stealth or evasion (no SYN-only scanning, no
  fragmentation, no timing tricks to dodge IDS)
- exploit anything
- test credentials
- detect vulnerabilities

**Only scan hosts you're authorized to scan.** Port scanning networks you
don't own or have permission to test can violate laws and terms of
service depending on where you are and what you're scanning.

## V2 roadmap

Not in V1, planned for later:

- HTTP probing (actually check what's serving on web ports)
- TLS inspection (cert details, protocol versions)
- Basic protocol validation (confirm a port is speaking what it claims)
- DNS diagnostics
- JSON/CSV output
- Maybe a simple dashboard

None of that exists yet. If a claim above says V1 doesn't do it, it
doesn't do it.
