# socks5

A fork of [armon/go-socks5](https://github.com/armon/go-socks5), copied into
this repository in March 2026 and edited in place since. It is not a
dependency: there is no upstream to pull from any more, and changes go straight
into these files. `LICENSE` is the original MIT licence and stays.

## What this fork does that the original does not

- **`UDP ASSOCIATE` (`0x03`) is implemented.** The original lists it under
  TODO. The relay keeps two sockets per association - one the client talks to,
  one the internet is reached from - in `associate.go`.
- **A command the RFC does not define: `0x83` (`UDPTunnelCommand`).** It is
  UDP multiplexed over the TCP connection, so a datagram never leaves the
  tunnel as a datagram, which is what makes a WebRTC, QUIC or DNS leak
  impossible. `s5client` rewrites `0x03` into `0x83`; the server answers it in
  `handleUDPTcpmux`. The framing is `[length uint16][SOCKS5 UDP header]
  [payload]` and is specified in section 10 of `docs/veil-spec.md`. Both sides
  have to change together.
- **The connection has an explicit state machine.** `internal/session` owns the
  lifecycle and every deadline that applies to it; this package drives it and
  does not keep timeouts of its own (`phase.go`, `deadline.go`).
- **Authentication is pluggable and account-aware.** `CredentialStore` reaches
  `internal/userstore` for Argon2id passwords, quotas and validity dates, and
  the tunnel can name its member before SOCKS5 starts (`Config.TunnelIdentity`),
  in which case the server answers `NoAuth` and the session carries that name.
- **The handshake is read through one buffer** (`bufio.Reader`, `socks5.go`)
  instead of a syscall per byte, and the buffer is handed on to the request
  parser and to the UDP tunnel, so nothing a client sent early is lost.
- **Relaying is `internal/relay`**, with half-close, a pooled buffer and
  per-account byte counting, not a pair of bare `io.Copy` calls.
- **`ServeContext` is the entry point.** Accepting stops when the context is
  cancelled, connection goroutines recover from panics, and replies are built
  from sized slices - the original's fixed `[260]byte` reply buffer could be
  written past by a 255-byte FQDN.

## What it kept

The shape of the original: `Config`, `Server`, `Authenticator`, `RuleSet`,
`NameResolver`, `AddrSpec` and the request-handling flow are still recognisably
armon's, and so are the names. Anything not listed above behaves as it did.
