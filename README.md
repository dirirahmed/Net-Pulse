# Net-Pulse v2: Network Diagnostics Engine

## The point of this project

Net-Pulse is a network diagnostic tool built in Go. A standard `ping` only tells
you whether a machine is on. Net-Pulse tells you whether the *services* on that
machine are actually functioning: whether the name resolves, whether the port
accepts a connection, whether the TLS certificate is valid, and whether the web
server answers.

V1 was a concurrent port scanner. V2 is a reusable diagnostics engine with a CLI
on top of it. The networking code produces structured results and never prints
anything, so the same engine can back an API and a results database later
without being rewritten.

## What it does

**DNS diagnostics** - resolved addresses, CNAME, lookup duration, and a
classified error when resolution fails or times out.

**Port scanning** - configurable port lists and ranges, scanned by a fixed
worker pool. Each port reports open / closed / timeout / error plus how long the
connection took. Known ports are mapped to the service they usually carry.

**TCP diagnostics** - a real connection to the target port, with duration,
local/remote addresses and a classified failure reason.

**TLS diagnostics** - a real, *verifying* handshake. Records the negotiated
version and cipher, ALPN, the certificate chain, expiry, and whether validation
succeeded. Verification is never disabled to make a probe look successful: when
a chain fails to validate, the result stays a failure and the certificate is
re-read separately only so you can see what was wrong with it.

**HTTP/HTTPS diagnostics** - status code, total duration, time to first byte,
the redirect chain, interesting response headers, and classified transport
errors.

## Usage

```bash
go run . example.com
go run . https://example.com/health
go run . -checks dns,tls -ports 443,8443 example.com
go run . -json 1.1.1.1 > scan.json
```

Flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `-ports` | `default` | `default`, `all`, or a list like `22,80,443,8000-8010` |
| `-checks` | `all` | any of `dns,ports,tcp,tls,http` |
| `-concurrency` | `100` | maximum simultaneous port connections |
| `-timeout` | `2s` | TCP connect timeout per port |
| `-dns-timeout` | `3s` | DNS lookup timeout |
| `-tls-timeout` | `5s` | TLS handshake timeout |
| `-http-timeout` | `10s` | HTTP request timeout |
| `-total-timeout` | `60s` | budget for the whole scan |
| `-method` | `GET` | HTTP method |
| `-follow` | `true` | follow redirects |
| `-max-redirects` | `10` | redirect limit |
| `-json` | `false` | emit the structured report instead of text |
| `-show-closed` | `false` | list closed and filtered ports too |

Running with no target keeps the V1 behaviour and scans `8.8.8.8`.

## Layout

```
main.go                     entry point only
internal/result/            structured result types (pure data, JSON ready)
internal/probe/             dns, tcp, scan, tls, http probes + error classification
internal/engine/            target parsing and orchestration into one Report
internal/cli/               flags and text rendering
internal/safety/            target checks for callers that don't own the target
```

The dependency direction is one-way: `cli -> engine -> probe -> result`. Nothing
below `cli` knows how results are displayed.

## Scanning untrusted targets

The CLI assumes you own what you point it at, so it does no checking. Anything
that takes a target from someone else cannot assume that, and `internal/safety`
exists for those callers:

```go
guard := &safety.Guard{}
if err := guard.CheckTarget(ctx, target.Host); err != nil {
    return err // loopback, private, link-local, reserved, or a local hostname
}

opts := engine.DefaultOptions()
opts.Dialer = guard.Dialer()   // enforced again at connect time
report := engine.Run(ctx, target, opts)
```

Two checks, because neither is enough alone. `CheckTarget` resolves the name
and refuses it if *any* answer is reserved. `Dialer` re-checks inside
`net.Dialer.Control`, which runs after resolution with the address the kernel
is about to connect to — that is what catches a name resolving differently the
second time, and redirects pointing at internal hosts.

Every probe dials through whatever dialer it is handed, so setting
`Options.Dialer` once covers ports, TCP, TLS and HTTP together. Setting
`AllowPrivate` turns both checks off for local development.

## Tests

```bash
go test ./...
go test -race ./...
go test -bench=. ./internal/probe
```

Tests use loopback listeners, `httptest` servers and a fake DNS resolver, so
they do not need internet access.
