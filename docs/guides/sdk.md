# Architecture

S5Core provides a server and a Go SDK. It also ships an optional local SOCKS5
adapter for applications that do not implement obfs/WSS themselves:

| Binary | Role | Description |
|--------|------|-------------|
| `s5core` | **Server** | SOCKS5 proxy with optional obfuscation layer. Deployed on the remote server. |
| `s5client` | **Optional adapter** | Local SOCKS5 proxy that wraps traffic in an obfuscation tunnel. Runs on the user's machine. |

### Without Obfuscation (Standard Mode)
```
TCP: App → s5core:1080 (plain SOCKS5) → Internet
UDP: App → s5core:1080 (UDP Associate) → s5core (UDP relay) → Internet
```

> **The UDP relay uses two sockets per association.** The port `s5core` hands
> back in its `UDP ASSOCIATE` reply speaks to the client and to nobody else:
> a datagram arriving there from any other address is dropped, not forwarded.
> Targets are reached from a second socket, on a port of its own, bound to the
> same `BIND_IP`. With one socket for both sides the relay had to guess from
> the source address whether a datagram was a command or a reply, so any host
> that found the advertised port could have its datagrams delivered to the
> client, and a client asking for a service on its own address got the replies
> parsed as commands.

Both UDP modes resolve domain destinations outside the packet reader. Each
association coalesces pending requests for the same name, keeps at most four
lookups and 64 queued domain packets, and reuses up to 256 successful results
for 30 seconds. The resolver interface supplies no DNS TTL; this is a local
reuse interval. A full DNS queue drops domain packets. IP packets keep their
direct send path and do not compete for that queue. Closing the association
cancels its lookups; destination rules are checked before resolution.

> **A fragmented datagram is dropped, on both UDP paths.** `FRAG` other than
> zero says the datagram is one piece of a larger one, and nothing here puts
> the pieces back together, so RFC 1928 section 7 says to drop it. This used
> to forward the piece instead, on the grounds that some clients write
> something other than zero there - which handed the target part of a message
> as though it were all of it. A DNS query cut in two is not a shorter query.
> If an application really does set `FRAG`, its datagrams now time out at the
> application instead of being answered wrongly by the destination.

### With Obfuscation (Dual-Port Mode)

Example using the optional `s5client` adapter. A compatible client can implement
the encrypted transport directly, without a local SOCKS5 listener.

```
TCP: App → s5client:1080 → [encrypted tunnel] → s5core:OBFS_PORT → Internet
UDP: App → s5client:1080 → [UDP-over-TCP mux] → s5core:OBFS_PORT → Internet   ← no UDP leaks!
```

> **Important:** When obfuscation is enabled, the server listens on **two ports simultaneously**:
> - `PROXY_PORT` (default `1080`) - plain SOCKS5 for direct/local connections
> - `OBFS_PORT` (default `1443`) - obfuscated connections from compatible clients, including `s5client`
>
> **Pick `OBFS_PORT` yourself, outside the 443 family.** On 443, 8443 and 1443
> a middlebox expects a TLS ClientHello: a version byte, a length, a session
> id, a server name. This transport sends 32-bit length prefixes and
> high-entropy bytes from the first one, so the very port that is supposed to
> look ordinary is where the traffic stands out most. An unremarkable high
> port (say `27015`) draws no such expectation. If you want the tunnel on 443,
> use the WebSocket transport (`WS_ENABLED`), which speaks real TLS and serves
> a decoy site to everyone else.

### Packages

| Package | What it owns |
|---|---|
| `pkg/s5server` | The SDK: lifecycle, listeners, configuration, telemetry. What an embedder imports. |
| `pkg/obfs` | The obfuscation format - frames, keys, keepalive, replay history. |
| `pkg/veil` | The prologue scheme and key derivation the format is parameterised by. |
| `pkg/transport/ws`, `pkg/transport/tlsdecoy` | Delivering bytes: WebSocket with frame shaping, and the TLS listener that shares a socket between the tunnel and a decoy site. |
| `internal/socks5` | The SOCKS5 message codec (a much-extended fork of `armon/go-socks5`). |
| `internal/relay` | Copying and metering bytes, and passing on the end of a stream. |
| `internal/session` | The connection state machine - three orthogonal regions; see [Connection states](operations.md#connection-states). |
| `internal/identity` | The access decision: credentials, and the lockout that keys on the client rather than on the account. |
| `internal/userstore` | The accounts file, quotas and validity dates. |

The boundaries between them are not a convention: `internal/arch/arch_test.go`
asks `go list` what each package actually reaches and fails by name when one
reaches somewhere it should not - the codec into telemetry, a transport into
the payload cryptography, the relay into either. Each rule carries its reason
in one line, which is what a failure prints.

---

## SDK Usage (Embedding in your Go App)

The module requires Go 1.27.0 or newer, and its `go.mod` sets `toolchain go1.27.4`.
That directive is not a strict compiler pin, so check the actual `go version`
when reproducing measurements or verifying an SDK build.

S5Core is built to be the networking engine for your custom proxy managers or Web-UIs. You can import it and control the proxy programmatically.

```go
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/mazixs/S5Core/pkg/s5server"
)

func main() {
	cfg := s5server.DefaultConfig()
	cfg.Port = "1080"
	cfg.RequireAuth = true
	// Enable modern user store
	cfg.UsersFile = "users.json"
	cfg.TrafficFlushInterval = 30 * time.Second

	// Enable obfuscation
	cfg.ObfsEnabled = true
	cfg.ObfsPort = "27015"
	cfg.ObfsPSK = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH" // 32 bytes
	cfg.ObfsMaxPadding = 256
	cfg.ObfsMTU = 1400

	// Initialize the server
	srv, err := s5server.NewServer(cfg)
	if err != nil {
		panic(err)
	}

	// Update whitelisted IPs on the fly
	srv.UpdateWhitelist([]string{"192.168.1.100"})

	// Start the server (blocks until context is canceled)
	slog.Info("Starting S5Core SDK...")
	if err := srv.Start(context.Background()); err != nil {
		panic(err)
	}
}
```

`NewServer` validates the configuration before anything is listening. To pass
optional settings such as TCP Fast Open, WSS early data or periodic UDP
reports, use `s5server.NewServerWithOptions(cfg, opts)` with a
`s5server.ServerOptions` value.

Use `s5server.InitTelemetry` to populate `Config.Telemetry` with all available
OpenTelemetry instruments. If you supply your own, a missing required
instrument is reported by name at startup; instruments added in 2.4 are
optional. A nil `Config.Telemetry` disables metrics.

`Start` returns when the context is canceled; call `Stop` afterwards to flush
the traffic counters and wait for the live sessions (see [Shutdown](operations.md#shutdown)).

### Runtime telemetry ownership

`InitTelemetry` creates the S5Core instruments on the OTel meter provider it is
given, or on the global one when it gets nil. Neither it nor the server
registers Prometheus Go or process collectors, and an OTel meter provider alone
exports no runtime metrics. The embedding application owns its registry,
exporter, meter provider, HTTP service and their shutdown.

Register one Go collector and one process collector per metrics endpoint, even
when the application embeds several S5Core servers: runtime measurements always
describe the whole process.

Servers may share one `Telemetry`. They then write to the same instruments, and
no label names the server. Counters and up-down counters such as
`s5core_connections_active` add up across them. A gauge that each server
reports at scrape time, such as `s5core_sessions`, shows the values of one of
the servers, not their sum.

The setup below gives the endpoint the collectors of the standalone `s5core`:
the Go collector with its default families and the eleven `runtime/metrics`
sources listed in [Go runtime and process metrics](operations.md#go-runtime-and-process-metrics),
the process collector, and the handler's own `promhttp_metric_handler_*`
counters. It uses a registry of its own and leaves the global default registry
alone. Call it once at process startup, then pass the returned telemetry to each
`Config.Telemetry`.

```go
package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/mazixs/S5Core/pkg/s5server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// runtimeMetricNames are the runtime/metrics sources exported on top of the
// Go collector's defaults, the same eleven as in the standalone s5core.
var runtimeMetricNames = []string{
	"/sched/pauses/total/gc:seconds",
	"/sched/latencies:seconds",
	"/gc/cycles/total:gc-cycles",
	"/gc/cycles/forced:gc-cycles",
	"/cpu/classes/gc/total:cpu-seconds",
	"/cpu/classes/gc/mark/assist:cpu-seconds",
	"/cpu/classes/gc/mark/idle:cpu-seconds",
	"/cpu/classes/total:cpu-seconds",
	"/gc/heap/live:bytes",
	"/gc/limiter/last-enabled:gc-cycle",
	"/sync/mutex/wait/total:seconds",
}

// newProcessTelemetry builds the registry, the telemetry for Config.Telemetry
// and the handler for /metrics. Call it once per process.
func newProcessTelemetry(ctx context.Context) (
	*s5server.Telemetry, *sdkmetric.MeterProvider, http.Handler, error,
) {
	quoted := make([]string, len(runtimeMetricNames))
	for i, name := range runtimeMetricNames {
		quoted[i] = regexp.QuoteMeta(name)
	}
	registry := prometheus.NewRegistry()
	for _, c := range []prometheus.Collector{
		collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{
				Matcher: regexp.MustCompile("^(?:" + strings.Join(quoted, "|") + ")$"),
			},
		)),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		if err := registry.Register(c); err != nil {
			return nil, nil, nil, err
		}
	}
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, nil, nil, err
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	telemetry, err := s5server.InitTelemetry(provider)
	if err != nil {
		return nil, nil, nil, errors.Join(err, provider.Shutdown(ctx))
	}
	handler := promhttp.InstrumentMetricHandler(registry,
		promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	return telemetry, provider, handler, nil
}
```

Mount the returned handler on `/metrics` in the application's own HTTP mux, with
explicit read, write and idle timeouts as in the standalone service.
`promhttp.Handler()` serves the default registry and would omit this setup's
metrics. The process collector exports the families the host platform supports.
Do not register a second base Go collector in this registry, which fails, or
merge the default gatherer into it, which makes the scrape fail on duplicate
families. The exporter takes the registry through
[`WithRegisterer`](https://pkg.go.dev/go.opentelemetry.io/otel/exporters/prometheus@v0.69.0#WithRegisterer).

The setup starts no listener and no background goroutine: the metrics are read
when the handler is scraped. Stop each server and shut down the metrics HTTP
service before calling `provider.Shutdown` with a bounded context.

### Acting on behalf of an account

`Server.AddUser`, `RemoveUser`, `SetRole` and `UpdateWhitelist` are the process
owner's API: they perform no role check, because a caller holding a `*Server`
can also call `Stop`. That is the right answer for a program that embeds the
server and the wrong one for what usually sits in front of it - a control
panel or an HTTP API, where a request arrives on behalf of an account and the
account is not the process.

`Server.As(username)` returns the same actions bound to an account, each
checked against that account's [role](accounts.md#roles) first:

```go
admin, err := srv.As(requestUser) // fails for a name that is not an account
if err != nil {
	return err
}
if err := admin.AddUser("bob", password); err != nil {
	// *s5server.ErrNotAllowed when the role may not; 403 belongs here
	return err
}
accounts, err := admin.Accounts() // names, roles and quotas - no hashes, no keys
key, err := admin.TunnelKey("bob") // admin only: this is OBFS_MEMBER_KEY
if admin.Can(s5server.ManageAccountsAction) {
	err = admin.SetRole("bob", s5server.RoleOperator)
}
```

The account model - `Role`, `Action`, `Account`, `Policy`, `ErrNotAllowed` and
the role and action constants - is named in this package. The types themselves
live in `internal/identity`, where the connection path uses them, and these are
aliases rather than copies, so a value passed in is the value the server
checks. They exist because an external module cannot import `internal/...`: a
method taking `identity.Action` would be callable from this repository's tests
and from nowhere else.

`Admin.Can(action)` answers the same question without performing it, for a
panel deciding what to show. `Admin.Actor()` is the account itself, without its
key, and `Admin.Role()` is what it may do.

A handle pins the account incarnation that existed at `As`, rather than the
current owner of a reusable name. Every call reads that incarnation's current
role and policy. Demotion, expiry, disabling, removal or replacement reaches
existing handles. Removing an account and recreating the same name and ID does
not revive an old handle. Ordinary reloads retaining the same ID preserve its
binding; changing the name revokes handles issued under the old name.
Issuing a handle is not authentication - the embedding application still has to
establish who the request is from.

The tunnel key never travels with the account list. It is what an account is on
the wire, so a listing that carried one would let anyone with
`view accounts` raise a tunnel as any member; handing a key out is
`manage accounts`, which only `admin` has.

### Runtime controls and run IDs

`UpdateWhitelist`, `UpdateTimeouts`, `UpdateHandshakeTimeout` and
`UpdateSessionTimeouts` retain their latest values on the `Server`, including
calls before the first `Start` or while stopped. Each new listener inherits
those values after `Stop` followed by `Start`. Timeout updates apply to the
next accepted connection; established sessions keep their original budgets.
Invalid whitelist updates do not replace the last valid restriction.

`Boot()` is safe during concurrent startup. Each accepted `Start` creates a
new eight-digit hexadecimal run ID used in the service log and session journal.
Before the first run it returns a provisional ID created by `NewServer`;
`Stop` retains the last run ID. Rejected overlapping `Start` calls do not
change it.

Authenticated TCP and UDP sessions pin the same account incarnation for access
checks and traffic counters. Replacement or removal/recreation revokes old
sessions at their existing policy-check boundaries; neither their traffic nor
permissions are reassigned to the new owner of the name. This does not change
native UDP probe cadence or the wire format.

[Documentation index](../README.md) · [Project home](../../README.md)
