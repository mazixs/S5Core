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

S5Core is built to be the networking engine for your custom proxy managers or Web-UIs. You can import it and control the proxy programmatically.

```go
package main

import (
	"context"
	"log/slog"

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

`NewServer` validates the configuration before anything is listening, so a
mistake is a returned error and not a panic on the first connection. In
particular, `Config.Telemetry` must come from `s5server.InitTelemetry`: it is a
struct of OpenTelemetry instruments, and one assembled by hand - or carried
over from a version with fewer fields - is rejected by name rather than
dereferenced later. Leaving it nil is fine and disables metrics.

`Start` returns when the context is canceled; call `Stop` afterwards to flush
the traffic counters and wait for the live sessions (see [Shutdown](operations.md#shutdown)).

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

A handle holds a name, not a role. Every call re-reads the account, so a
demotion, a removal or a disabling reaches the handles that were issued before
it: an admin that demotes itself has demoted itself, and a handle to an account
that is gone fails rather than falling back to the least privileged role.
Issuing a handle is not authentication - the embedding application still has to
establish who the request is from.

The tunnel key never travels with the account list. It is what an account is on
the wire, so a listing that carried one would let anyone with
`view accounts` raise a tunnel as any member; handing a key out is
`manage accounts`, which only `admin` has.

[Documentation index](../README.md) · [Project home](../../README.md)
