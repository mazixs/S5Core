# S5Core — Finite State Machine Design Document

**Version:** 1.0  
**Date:** 2026-05-30  
**Author:** Senior Go Engineer (Code Review Agent)

---

## 1. Executive Summary

The current SOCKS5 / obfuscation / UDP-relay logic in S5Core is **implicitly** stateful. State transitions are scattered across function calls (`ServeConnContext -> authenticate -> handleRequest -> handleConnect/Associate/UDPTcpmux`). There is no central state machine type, no per-state timeout enforcement, and no formal guard logic. This document:

1. Reverse-engineers the **current de-facto FSM**.
2. Documents the **gaps and hazards** that arise from the implicit design.
3. Proposes a **unified, explicit FSM architecture** for the next major refactor.

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
| `PROXY_TCP` has no half-close sub-states | EOF from client immediately triggers full `Close()` on both sides (see P1-6). |
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
| No `CloseWrite` state | Cannot signal half-close through the encrypted tunnel (P1-6). |
| Replay window is implicit | Lives inside `conn` struct but is not a state variable; hard to inspect or reset. |
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

**New frame types:**

| Type Byte | Meaning |
|-----------|---------|
| `0x00` | Data frame (current) |
| `0x01` | CloseWrite frame (signals half-close) |
| `0x02` | Keep-alive frame (zero payload) |

**Transitions:**

- `ObfsStateReady` + `Write(payload)` -> `ObfsStateFrameWrite` -> encrypt -> emit -> back to `Ready`.
- `ObfsStateReady` + `Read()` -> `ObfsStateFrameRead` -> read header -> `ObfsStateFrameBody` -> read body -> `ObfsStateDecrypt` -> return payload -> back to `Ready`.
- `ObfsStateReady` + `CloseWrite()` -> send frame type `0x01` -> `ObfsStateHalfClosed`.
- `ObfsStateReady` + receive frame type `0x01` -> propagate `CloseWrite()` to underlying `net.Conn`.

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
