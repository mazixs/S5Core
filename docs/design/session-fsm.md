# S5Core — Finite State Machine Design Document

**Version:** 1.1  
**Date:** 2026-05-30, section 6 added 2026-09-19  
**Author:** Senior Go Engineer (Code Review Agent)

> **How to read this document (plan task Ф6-6).** Sections 2 to 5 are the
> as-is analysis of 2026-05-30 and the refactor they proposed. They describe
> the code **before** `internal/session` existed and are kept for the
> reasoning, not as a description of the repository. **Section 6 is the
> current state**: what plan task Ф6-1 actually implemented, and where it
> departs from the proposal. When the two disagree, section 6 is right.

---

## 1. Executive Summary

When this was written, the SOCKS5 / obfuscation / UDP-relay logic in S5Core was **implicitly** stateful (it is not any more - see section 6). State transitions are scattered across function calls (`ServeConnContext -> authenticate -> handleRequest -> handleConnect/Associate/UDPTcpmux`). There is no central state machine type, no per-state timeout enforcement, and no formal guard logic. This document:

1. Reverse-engineers the **current de-facto FSM**.
2. Documents the **gaps and hazards** that arise from the implicit design.
3. Proposes a **unified, explicit FSM architecture** for the next major refactor.

Section 6 records what was actually implemented in `internal/session` (plan
task Ф6-1) and where it departs from the proposal in sections 3-5.

---

## 2. Current State (As-Is)

### 2.1 Server-Side Connection FSM (Plain SOCKS5)

```text
+---------+   TCP_ACCEPT   +--------------+
|  CLOSED |--------------->| WAIT_VERSION |
+---------+                +------+-------+
                                  | READ(ver)
                                  | ver == 0x05
                                  v
                          +---------------+
                          | WAIT_AUTH_MTH |<-- READ(methods)
                          +-------+-------+
                                  | methods validated
                                  v
                          +---------------+
                          |  AUTHENTICATE |<-- sub-negotiation
                          +-------+-------+
                                  | success
                                  v
                          +---------------+
                          |  WAIT_REQUEST |<-- READ(req header + dest)
                          +-------+-------+
                                  | parse OK
                    +-------------+-------------+
                    v             v             v
              +---------+  +----------+  +-------------+
              | PROXY_TCP|  | PROXY_UDP|  | PROXY_UDPTCP|
              | (0x01)  |  | (0x03)   |  | (0x83)      |
              +----+----+  +----+-----+  +------+------+
                   |            |               |
                   |   DATA_IN / DATA_OUT      |
                   |            |               |
                   v            v               v
              +-------------------------------------+
              |           CLOSED (defer)            |
              |  conn.Close() + target.Close()      |
              +-------------------------------------+
```

**Key observations:**

| Observation | Risk |
|-------------|------|
| No explicit `State` variable | Impossible to introspect or limit per-state behavior. |
| `WAIT_VERSION` and `WAIT_AUTH_MTH` share the same read timeout (`timeoutConn`) | A slow client can burn a connection slot indefinitely by sending one byte every 29 s. |
| `AUTHENTICATE` has no sub-state | `UserPassAuthenticator` is a blocking black-box; the outer server cannot enforce a per-auth timeout. |
| `WAIT_REQUEST` allows any command | No pre-validation of address type bounds before `readAddrSpec`. |
| `PROXY_TCP` has no half-close sub-states | The relay half-closes each direction as it ends (`halfClose` in `internal/socks5/request.go`) and Ф4-9 made that signal cross the tunnel, but the state machine still has no state for "one direction closed": how long a half-closed relay may live is not expressed anywhere. |
| `PROXY_UDP` uses polling (`SetReadDeadline(500ms)`) instead of event-driven select | Wastes CPU and adds 0-500 ms latency to UDP relay teardown. |
| `PROXY_UDPTCP` (0x83) has no keep-alive / idle-timeout | A silent client holds the socket forever. |

### 2.2 Obfuscation Layer FSM (obfsConn)

```text
+----------+   NewConn()   +-------------+
|  INIT    |-------------->| CIPHER_READY|
+----------+               +------+------+
                                  |
              +-------------------+-------------------+
              | READ(frame header + body)             | WRITE(payload)
              v                                       v
       +-------------+                         +-------------+
       | FRAME_READ  |                         | FRAME_WRITE |
       | decrypt     |                         | encrypt     |
       | validate    |                         | seal + pad  |
       +------+------+                         +------+------+
              |                                       |
              +-------------------+-------------------+
                                  | error
                                  v
                           +------------+
                           |   ERROR    |
                           | close conn |
                           +------------+
```

**Key observations:**

| Observation | Risk |
|-------------|------|
| No handshake state | `NewConn` instantiates the cipher immediately; there is no version / capability negotiation. |
| ~~No `CloseWrite` state~~ | Closed by Ф4-9: the frame carries a kind byte, `CloseWrite` sends a FIN frame, and the peer's `Read` ends with `io.EOF` while the reverse direction keeps working. The signal no longer depends on the transport underneath, which is what made it work over WebSocket. |
| ~~Replay window is implicit~~ | Closed by Ф4-4: the per-connection nonce window is gone, replaced by `obfs.SaltHistory` on the server - one explicit, inspectable structure shared by all obfuscated listeners. |
| `FRAME_READ` allocates if `frameSize > cap(readBuf)` | DoS vector: send a 128 KB frame and force a heap alloc on every read. |

### 2.3 Authentication & Account FSM

```text
+---------+   Valid(user,pass)   +----------+
|  CLEAN  |--------------------->|  CHECK   |
+---------+                      +----+-----+
                                      |
                    +-----------------+-------------+
                    | fail < max      | fail >= max | success
                    v                 v             v
              +----------+     +----------+      +----------+
              | SUSPICIOUS|     |  BANNED  |      |  CLEAN   |
              | inc fail  |     | timer    |      | reset    |
              +----------+     +----------+      +----------+
```

**Key observations:**

| Observation | Risk |
|-------------|------|
| `SUSPICIOUS` and `BANNED` are stored in unbounded maps | No eviction of stale entries (P0-5). |
| `CHECK` holds a global write mutex | Serializes all logins (P0-4). |
| No per-IP state machine | `fail2ban` keys by username only; IP-level protection is missing. |

### 2.4 Client-Side FSM (s5client)

```text
+---------+   ACCEPT   +--------------+
|  IDLE   |----------->| LOCAL_GREET  |
+---------+            +------+-------+
                              | read greeting
                              v
                        +--------------+
                        | LOCAL_REQUEST|
                        +------+-------+
                              | read CONNECT/ASSOCIATE
                              v
                        +--------------+
                        |  OBFS_DIAL   |
                        +------+-------+
                              | TCP + NewConn
                              v
                        +--------------+
                        |  OBFS_AUTH   |
                        +------+-------+
                              | auth OK
                    +---------+----------+
                    v                    v
             +----------+        +--------------+
             | TCP_RELAY|        | UDP_RELAY    |
             | (0x01)   |        | (0x83 tunnel)|
             +----+-----+        +------+-------+
                  |                     |
                  v                     v
             +----------------------------------+
             |          CLOSED                   |
             |  (defer close both conns)         |
             +----------------------------------+
```

**Key observations:**

| Observation | Risk |
|-------------|------|
| `LOCAL_GREET` always replies "no auth required" | Local apps are not authenticated; any local process can use the tunnel. |
| `OBFS_DIAL` has no retry or backoff state | Single network hiccup kills the local connection. |
| `OBFS_AUTH` does not validate server identity | PSK only; no certificate pinning or downgrade protection. |
| `UDP_RELAY` has no MTU / fragmentation state | Oversized UDP packets (> MTU) are simply dropped by the TCP framing layer without ICMP feedback. |

---

## 3. Desired State (To-Be)

### 3.1 Design Principles

1. **Explicit state types** — every connection carries a typed `ConnState` constant.
2. **Per-state timeouts** — each transition has its own SLA (e.g. `T1_Version = 5s`, `T2_Auth = 10s`, `T3_Dial = 30s`).
3. **Graceful half-close** — TCP proxy state splits into `PROXY_FULL <-> PROXY_HALF_CLOSE_WAIT`.
4. **Event-driven UDP** — replace polling with `select { case <-udpCh: ... case <-tcpDone: ... }`.
5. **Sharded fail2ban FSM** — per-IP and per-username state machines in lock-free shards.
6. **Observability hooks** — every transition emits an OpenTelemetry event for tracing.

### 3.2 Proposed Server Connection FSM

```go
type ConnState uint8

const (
    // Handshake
    StateInit ConnState = iota
    StateWaitVersion
    StateWaitAuthMethods
    StateAuthInProgress
    StateWaitRequest

    // Pre-proxy validation
    StateResolving      // DNS lookup
    StateRuleChecking   // FQDN / IP whitelist
    StateDialing        // outbound TCP connect

    // Active proxy
    StateProxyTCP
    StateProxyTCPHalfClose // one side sent FIN
    StateProxyUDP
    StateProxyUDPTunnel    // 0x83

    // Shutdown
    StateDraining      // signal received, flush buffers
    StateClosed
    StateError
)

type ConnEvent uint8

const (
    EventVersionRead ConnEvent = iota
    EventAuthMethodSelected
    EventAuthSuccess
    EventAuthFailure
    EventRequestRead
    EventResolveOK
    EventResolveFail
    EventDialOK
    EventDialFail
    EventDataIn
    EventDataOut
    EventFinReceived
    EventError
    EventShutdownSignal
)

// Transition is pure logic: (state, event) -> (nextState, action, error)
type Transition struct {
    Guard   func(*Request) bool
    Action  func(*ServerConn) error
    Next    ConnState
    Timeout time.Duration
}
```

#### 3.2.1 Transition Table (Server)

| Current State | Event | Guard | Action | Next State | Timeout |
|---------------|-------|-------|--------|------------|---------|
| `StateInit` | `TCP_ACCEPT` | — | set deadlines | `StateWaitVersion` | 5s |
| `StateWaitVersion` | `EventVersionRead` | `ver == 0x05` | read methods | `StateWaitAuthMethods` | 5s |
| `StateWaitVersion` | `EventVersionRead` | `ver != 0x05` | send error, close | `StateError` | — |
| `StateWaitAuthMethods` | `EventAuthMethodSelected` | method supported | run authenticator | `StateAuthInProgress` | 10s |
| `StateWaitAuthMethods` | `EventAuthMethodSelected` | no method | send 0xFF, close | `StateError` | — |
| `StateAuthInProgress` | `EventAuthSuccess` | — | — | `StateWaitRequest` | 10s |
| `StateAuthInProgress` | `EventAuthFailure` | — | inc fail2ban, close | `StateError` | — |
| `StateWaitRequest` | `EventRequestRead` | cmd == CONNECT | resolve, check rules | `StateResolving` | 30s |
| `StateWaitRequest` | `EventRequestRead` | cmd == ASSOCIATE | bind UDP | `StateProxyUDP` | — |
| `StateWaitRequest` | `EventRequestRead` | cmd == UDPTUNNEL | bind UDP, reply | `StateProxyUDPTunnel` | — |
| `StateResolving` | `EventResolveOK` | — | dial target | `StateDialing` | 30s |
| `StateResolving` | `EventResolveFail` | — | send hostUnreachable | `StateError` | — |
| `StateDialing` | `EventDialOK` | — | send success | `StateProxyTCP` | — |
| `StateDialing` | `EventDialFail` | — | send failure code | `StateError` | — |
| `StateProxyTCP` | `EventFinReceived` | — | `CloseWrite()` to peer | `StateProxyTCPHalfClose` | 60s |
| `StateProxyTCP` | `EventError` | — | close both | `StateClosed` | — |
| `StateProxyTCPHalfClose` | `EventFinReceived` | — | close both | `StateClosed` | — |
| `StateProxyTCPHalfClose` | `EventError` | — | close both | `StateClosed` | — |
| `StateProxyUDP` | `EventError` | — | close UDP + TCP | `StateClosed` | — |
| `StateProxyUDPTunnel` | `EventError` | — | close all | `StateClosed` | — |
| *Any* | `EventShutdownSignal` | — | set `StateDraining` | `StateDraining` | 30s |
| `StateDraining` | buffer empty | — | close | `StateClosed` | — |

#### 3.2.2 Half-Close Sequence (TCP)

```text
Client                    Server (FSM)
  |                         StateProxyTCP
  |-- FIN ----------------->|
  |                         | EventFinReceived
  |                         | Action: target.CloseWrite()
  |                         | Next: StateProxyTCPHalfClose
  |                         |
  |<-- data (last) ---------|
  |<---------- FIN ---------| target EOF
  |                         | Action: client.CloseWrite()
  |                         | Next: StateClosed
```

This requires `obfsConn` to support `CloseWrite()` (see section 3.4).

### 3.3 Proposed Obfuscation FSM

```go
type ObfsState uint8

const (
    ObfsStateInit ObfsState = iota
    ObfsStateReady        // cipher initialized
    ObfsStateFrameRead    // reading 4-byte header
    ObfsStateFrameBody    // reading ciphertext
    ObfsStateDecrypt      // AEAD open + replay check
    ObfsStateFrameWrite   // building frame
    ObfsStateHalfClosed   // sent/received close frame
    ObfsStateError
)
```

**Frame types** (implemented by Ф4-8 and Ф4-9; the kind byte is the first byte
inside the AEAD):

| Type Byte | Meaning |
|-----------|---------|
| `0x00` | Data frame |
| `0x01` | Keep-alive frame (zero payload, padded to the size of a real frame) |
| `0x02` | FIN frame (signals half-close, padded the same way) |

**Transitions:**

- `ObfsStateReady` + `Write(payload)` -> `ObfsStateFrameWrite` -> encrypt -> emit -> back to `Ready`.
- `ObfsStateReady` + `Read()` -> `ObfsStateFrameRead` -> read header -> `ObfsStateFrameBody` -> read body -> `ObfsStateDecrypt` -> return payload -> back to `Ready`.
- `ObfsStateReady` + `CloseWrite()` -> send frame type `0x02` -> `ObfsStateHalfClosed`; a later `Write` is refused.
- `ObfsStateReady` + receive frame type `0x02` -> `Read` returns `io.EOF` from then on. The half-close is **not** propagated to the underlying `net.Conn`: a WebSocket has none, and a transport that ends a stream differently from its peer ends it correctly on neither.

### 3.4 Proposed Fail2Ban FSM (Per-Identity)

```go
type BanState uint8

const (
    BanStateClean BanState = iota
    BanStateSuspicious
    BanStateBanned
)

type IdentityKey struct {
    IP       [16]byte // IPv6-compatible
    Username string   // optional
}

type IdentityFSM struct {
    state       atomic.Uint32 // BanState
    failCount   atomic.Uint32
    banExpiry   atomic.Int64  // unix nano
    lastAttempt atomic.Int64  // unix nano (for decay)
}
```

**Transitions:**

| State | Event | Guard | Action | Next |
|-------|-------|-------|--------|------|
| `Clean` | auth fail | `failCount < max` | `inc failCount` | `Suspicious` |
| `Suspicious` | auth fail | `failCount == max-1` | `set banExpiry = now + banTime` | `Banned` |
| `Banned` | auth attempt | `now < banExpiry` | reject fast | `Banned` |
| `Banned` | auth attempt | `now >= banExpiry` | reset failCount | `Clean` |
| `Clean` | auth success | — | reset failCount | `Clean` |

**Sharding:** Use 256 shards (`sync.RWMutex` per shard) keyed by `hash(ip) % 256` to eliminate the global lock.

### 3.5 Proposed Client FSM

```go
type ClientState uint8

const (
    ClientStateIdle ClientState = iota
    ClientStateLocalGreeting
    ClientStateLocalRequest
    ClientStateObfsDialing
    ClientStateObfsAuth
    ClientStateTCPRelay
    ClientStateUDPRelay
    ClientStateReconnecting // new: exponential backoff
    ClientStateClosed
)
```

**Key additions:**

1. **`ClientStateReconnecting`** — If the obfs tunnel drops, instead of closing the local connection immediately, enter a reconnect loop with exponential backoff (max 30 s). Buffer outbound data up to a limit (e.g. 64 KB) to survive brief network blips.
2. **Domain-routing state** — Before `ClientStateObfsDialing`, evaluate `RouteDomains`. If no match, enter `ClientStateDirectDial` (bypass tunnel entirely) rather than rejecting the request.
3. **UDP MTU guard** — In `ClientStateUDPRelay`, if a local UDP packet exceeds `OBFS_MTU - overhead`, fragment it or send an ICMP "Fragmentation Needed" echo back to the application.

---

## 4. Implementation Roadmap

### Phase 1 — Critical Fixes (P0)
1. Fix `sendReply` buffer size.
2. Replace `net.Dial` with `DialContext`.
3. Guard type assertions.
4. Shard fail2ban and remove Argon2id from hot mutex.
5. Cap Argon2id parameters.

### Phase 2 — Reliability (P1)
1. Make `metricsConn.Close` idempotent.
2. Preserve `trafficDelta` pointers across `ReloadUsers`.
3. Add `recover` in handler goroutine.
4. Implement `CloseWrite` on `obfsConn`.

### Phase 3 — Explicit FSM Refactor
1. Introduce `ConnState` / `ConnEvent` types in `internal/socks5`.
2. Refactor `ServeConnContext` into a `for state != StateClosed { state = s.transition(state, event) }` loop.
3. Add per-state timeouts via `context.WithTimeout`.
4. Replace UDP polling with event-driven `select`.

### Phase 4 — Client & Observability
1. Add `ClientState` machine to `s5client`.
2. Implement reconnect backoff (`ClientStateReconnecting`).
3. Emit OTel span events on every FSM transition.
4. Add Grafana dashboard panels per state (active half-closes, draining conns, banned identities).

---

## 5. Appendix: Current vs Desired Comparison

| Aspect | Current (Implicit) | Desired (Explicit FSM) |
|--------|--------------------|------------------------|
| State representation | Scattered booleans / return points | Typed `ConnState` constant |
| Timeout policy | One global `readTimeout` | Per-state SLA (`WaitVersion=5s`, `Dialing=30s`) |
| Error handling | `return err` bubbles up | Central `StateError` with structured logging |
| Half-close | Not supported for obfs | `StateProxyTCPHalfClose` + `CloseWrite` frame |
| UDP teardown | Polling `SetReadDeadline(500ms)` | `select` on `done` channel |
| Fail2ban | Global mutex, username-only | 256 shards, IP + username keys |
| Traffic reload | Map replacement (data loss) | In-place merge (pointer stability) |
| Observability | Connection-level counters | Per-state histograms + span events |

---

## 6. Implemented: Orthogonal Regions (`internal/session`, plan task Ф6-1)

Sections 2-5 are the design as it was written. This section is what was
actually built, and where it departs from the proposal above.

### 6.1 Three regions instead of one machine

Section 3.2 proposed one flat state list. Building it showed that the states
in that list change independently of each other: a frame can be half-read
while the protocol is relaying, and an account can run out at any point. A
flat machine would have to multiply those out - `RelayAwaitBodyInGrace` and
its siblings - so the implementation keeps them as three orthogonal regions,
each with its own transition table, in `internal/session`:

| Region | States | Owner |
|---|---|---|
| `protocol` | `accepted` → `handshake` → `dialing` → `relay` → `half_closed` → `closed` | `internal/socks5` |
| `frames` | `await_header` ⇄ `await_body` → `deliver`, or `frame_error` | `pkg/obfs` |
| `account` | `within_quota` → `grace` → `quota_exceeded`, or `expired` | `internal/userstore` via the relay |

The regions are stored as three atomics on one `session.Session`, so a
transition is a compare-and-swap and a call to the observer. There is no
`for state != Closed { state = transition(...) }` loop: the drivers stayed
where they were and now report what they do, which is what made the change
reviewable instead of a rewrite of the request path.

`Unframed` is not a state the frames region sits in - it is the region not
existing. The plain listener publishes no frames cells at all.

### 6.2 Kind is an attribute, not a state

`Relay` covers a TCP stream, a UDP association and the `0x83` tunnel. What
differs between them is which deadlines apply, not which transitions are
legal, so `Kind` (`Stream`/`Tunnel`) is set once by whoever entered the relay
and read by the deadline logic. Three relay states would have tripled the
transition table to express one boolean.

### 6.3 Per-state SLA replaces the single timeout

`session.SLA` carries `Handshake`, `Dial`, `ReadIdle`, `WriteIdle`,
`FrameBody` and `Grace`. The transport no longer knows about regimes: on each
read and write it asks the session for the deadline to arm
(`Session.ReadDeadline`/`WriteDeadline`), and the session answers from the
states it is in - the strictest of the applicable budgets. The string-based
`SetDeadlinePolicy` plumbing of the previous design is gone.

Two consequences worth keeping: a `Tunnel` in `relay` gets no idle deadline
at all, because it is silent by design; the same tunnel stopped mid-frame
still gets `FrameBody`, because that is a peer that owes bytes. One idle
timeout could not say both.

### 6.4 The one coupling

Orthogonal regions that never interact would be three metrics, not a state
machine. There is exactly one edge between them, and it is the reason the
account region exists as a region: `Session.Exhaust` moves `account` to
`grace` and, from there, moves `protocol` to `half_closed`. The quota takes
effect in flight - what is already on the wire drains for `SLA.Grace`,
nothing new is sent on - rather than at the next connection. With
`SLA.Grace == 0` the session ends where the quota is noticed, which is a
configuration choice (`QUOTA_GRACE`), not a missing default.

`internal/socks5/grace_test.go` is the test that pins this: a client whose
account runs out mid-transfer still receives the bytes already in flight, and
the protocol region is observed going `relay → half_closed → closed`.

### 6.5 Every transition is observable

`session.Observer` is called on each move, including the ones the machine
refuses (`illegal=true`) - a refused move is counted rather than silently
dropped, because an illegal transition is a bug in a driver and a metric is
how it surfaces. `pkg/s5server` turns the observer into
`s5core_session_transitions_total` and the registry of open sessions into the
`s5core_sessions` gauge, read at scrape time so the hot path pays one atomic
store per transition and nothing per metric.

This is what section 4's "Grafana dashboard panels per state" became, and it
is the direct answer to bug 1 of the bug report: connections parked waiting
for a reply to `CONNECT` are now a cell of their own
(`region="protocol", state="dialing"`) instead of being indistinguishable
from healthy ones in `s5core_connections_active`.

### 6.6 What section 3 still proposes and this does not do

- The client FSM (section 3.5) is unchanged; `cmd/s5client/transport.go`
  holds the transport policy and does not report regions.
- Fail2ban (section 3.4) stayed a sharded store in `pkg/s5server`, not a
  per-identity state machine. Its states have no deadlines and no ordering
  worth a table.
- OTel span events per transition (section 4) were not added. The counter
  and the gauge answer the questions that were asked of them; a span event
  per read would not.
