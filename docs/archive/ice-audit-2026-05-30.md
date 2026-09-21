# S5Core — ICE Audit Report (Intra-Code Evaluation)

**Auditor:** Senior Go Engineer (Code Review Agent)  
**Scope:** `internal/*`, `pkg/*`, `cmd/*`  
**Date:** 2026-05-30  
**Methodology:** Static analysis, data-flow tracing, race-condition detection, DoS / security surface review.

---

## Severity Legend

| Severity | Meaning | Action |
|----------|---------|--------|
| **P0** | Process crash, data corruption, exploitable DoS, or auth bypass. Fix immediately. | Block release |
| **P1** | Data loss, metrics corruption, degraded availability, or clear logic bug. Fix before next minor. | High priority |
| **P2** | Feature gap, sub-optimal shutdown, minor spec deviation, or maintenance debt. | Backlog |
| **P3** | Style, non-standard encoding, missing bounds, or cosmetic issues. | Nice-to-have |

---

## P0 — Critical

### P0-1 `sendReply` stack-buffer panic on maximum FQDN reply
**File:** `internal/socks5/request.go:348`  
**Code:**
```go
var msg [260]byte
// ...
msg[4+len(addrBody)] = byte(addrPort >> 8)        // panic when len(addrBody)==256
msg[4+len(addrBody)+1] = byte(addrPort & 0xff)    // msg[260] and msg[261] are OOB
```
**Impact:** A malicious client can send a `CONNECT` request with a 255-byte FQDN. When the server replies (success or failure) it writes past the fixed `[260]byte` array, causing a runtime panic that kills the serving goroutine and leaks the connection stack. If triggered repeatedly this becomes a remote DoS.  
**Remediation:** Replace the fixed array with a dynamically sized slice:
```go
msg := make([]byte, 0, 6+len(addrBody))
msg = append(msg, Socks5Version, resp, 0, addrType)
msg = append(msg, addrBody...)
msg = append(msg, byte(addrPort>>8), byte(addrPort&0xff))
```

---

### P0-2 Default TCP dial ignores `context.Context`
**File:** `internal/socks5/request.go:175-177`  
**Code:**
```go
dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
    return net.Dial(net_, addr)   // ctx is silently dropped
}
```
**Impact:** When `s.config.Dial` is not provided, `handleConnect` falls back to `net.Dial`, which does **not** accept a context. If the client sends a CONNECT to a black-holed host, the goroutine blocks in the kernel until the OS TCP timeout (≈ 2 min) regardless of server shutdown or per-request deadlines. This stalls graceful shutdown and exhausts goroutines / file descriptors under load.  
**Remediation:**
```go
dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
    return (&net.Dialer{}).DialContext(ctx, net_, addr)
}
```

---

### P0-3 Type-assertion panic on `target.LocalAddr()`
**File:** `internal/socks5/request.go:198`  
**Code:**
```go
local := target.LocalAddr().(*net.TCPAddr)
```
**Impact:** If a custom `Dial` returns a `net.Conn` whose `LocalAddr()` is not `*net.TCPAddr` (e.g. Unix socket, TLS wrapper, `net.Pipe`), the server panics. This breaks any SDK user providing a non-TCP dialer.  
**Remediation:**
```go
local, ok := target.LocalAddr().(*net.TCPAddr)
if !ok {
    // fallback to IPv4zero:0 or derive from BindIP
    local = &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}
```

---

### P0-4 Global mutex serializes Argon2id verification — authentication DoS
**File:** `pkg/s5server/server_core.go:274-306`  
**Code:**
```go
func (s *fail2banStore) Valid(user, password string) bool {
    s.mu.Lock()                 // ← held for the ENTIRE duration
    defer s.mu.Unlock()
    // ...
    valid := s.store.Valid(user, password) // Argon2id verify inside
```
**Impact:** `passwordhash.Verify` invokes `argon2.IDKey` with 64 MiB memory and 3 iterations — hundreds of milliseconds on a small VPS. Because `fail2banStore.Valid` takes a **write mutex**, every concurrent authentication request is serialized. A single slow login blocks all other logins. Under brute-force load the auth path becomes a bottleneck and legitimate users are timed out.  
**Remediation:**
1. Use `sync.RWMutex`.
2. Take `RLock` only to read ban / failure state.
3. If not banned, release the lock, then call `s.store.Valid` outside the critical section.
4. If validation fails, re-acquire `Lock` and update counters.

---

### P0-5 Unbounded memory leak in fail2ban maps
**File:** `pkg/s5server/server_core.go:258-306`  
**Code:**
```go
type fail2banStore struct {
    failures map[string]int
    banned   map[string]time.Time
}
```
**Impact:** Maps are keyed by username. A brute-force attack using random usernames (never repeating) fills `failures` and `banned` with entries that are **never evicted** because eviction only happens on a subsequent `Valid` call with the same key. On a long-running server this causes unbounded memory growth and eventual OOM.  
**Remediation:** Add a background janitor goroutine (or piggy-back on `Valid`) that periodically deletes entries where `banExpiry < now.Add(-someGrace)` and resets `failures` for non-banned users after a cooldown window (e.g. 1 hour).

---

### P0-6 Argon2id parameter DoS via crafted password hash
**File:** `internal/passwordhash/passwordhash.go:41-76`  
**Code:**
```go
var mem, iters, par int
fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par)
// ...
computedHash := argon2.IDKey(..., uint32(mem), uint32(iters), uint8(par), ...)
```
**Impact:** An attacker who can write or tamper with `users.json` (e.g. via file-permission misconfig, volume mount, or future file-upload feature) can inject a hash with `m=2147483647` or `t=4294967295`. `argon2.IDKey` will attempt to allocate gigabytes of RAM or burn CPU for minutes, causing an OOM or CPU denial of service on the next login attempt.  
**Remediation:** Enforce hard caps before calling `argon2.IDKey`:
```go
const maxMemory = 512 * 1024 // 512 MiB
const maxIters  = 10
const maxParallelism = 4
if mem > maxMemory || iters > maxIters || par > maxParallelism {
    return false, fmt.Errorf("argon2 parameters exceed safe limits")
}
```

---

## P1 — High

### P1-1 `metricsConn.Close` is not idempotent — negative active-connection metric
**File:** `pkg/s5server/server_core.go:244-248`  
**Impact:** `ServeConnContext` defers `conn.Close()`. `handleConnect` also calls `nc.Close()` on error. Both hit `metricsConn.Close`, decrementing the `ActiveConnections` UpDownCounter twice. Prometheus/Grafana will show negative active connections, breaking alerts and autoscaling logic.  
**Remediation:** Guard with `sync.Once`:
```go
type metricsConn struct {
    net.Conn
    telemetry *Telemetry
    closeOnce sync.Once
}
func (c *metricsConn) Close() error {
    c.closeOnce.Do(func() {
        if c.telemetry != nil {
            c.telemetry.ActiveConnections.Add(context.Background(), -1)
        }
    })
    return c.Conn.Close()
}
```

---

### P1-2 `ReloadUsers` causes per-user traffic data loss
**File:** `pkg/s5server/server.go:117-122` + `internal/userstore/store.go:94-131`  
**Impact:** `TrafficCounterFor` returns `*atomic.Int64` pointing to `entry.trafficDelta`. `Reload` replaces the entire `users` map with new `userEntry` structs. In-flight TCP proxy goroutines continue writing to the **stale** `atomic.Int64`. The new entry starts from `trafficDelta = 0`. The unflushed delta on the old pointer is never merged back, so traffic accounting resets to zero for active users after every reload.  
**Remediation:** Instead of replacing the map atomically, perform an in-place merge: iterate over existing entries, update mutable fields (password, limits, enabled), add new entries, remove deleted ones. Keep the same `*userEntry` (and its `trafficDelta`) for users that still exist.

---

### P1-3 No `recover` in connection goroutine — one panic kills the process
**File:** `internal/socks5/socks5.go:136`  
**Code:**
```go
go func(c net.Conn) { _ = s.ServeConnContext(ctx, c) }(conn)
```
**Impact:** Any panic (including the P0-1 array overflow) propagates to the top of the goroutine and crashes the entire binary. A single malicious packet can take down the server.  
**Remediation:**
```go
go func(c net.Conn) {
    defer func() {
        if r := recover(); r != nil {
            slog.Error("panic in socks5 handler", "recover", r)
        }
    }()
    _ = s.ServeConnContext(ctx, c)
}(conn)
```

---

### P1-4 `handleConnect` does not guard against nil `realDestAddr`
**File:** `internal/socks5/request.go:137-140`  
**Code:**
```go
req.realDestAddr = req.DestAddr
if s.config.Rewriter != nil {
    ctx, req.realDestAddr = s.config.Rewriter.Rewrite(ctx, req)
}
// ...
target, err := dial(ctx, "tcp", req.realDestAddr.Address()) // panic if nil
```
**Impact:** A misbehaving or misconfigured `Rewriter` that returns `nil` address causes a nil-pointer dereference in `Address()`.  
**Remediation:** Check `req.realDestAddr == nil` after `Rewrite` and return `serverFailure`.

---

### P1-5 `s5client` CONNECT reply buffer too small for max FQDN
**File:** `cmd/s5client/main.go:156-164`  
**Code:**
```go
connectResp := make([]byte, 256)
rn, err := obfsConn.Read(connectResp)
// ...
clientConn.Write(connectResp[:rn])
```
**Impact:** A server reply with a 255-byte FQDN is 262 bytes on the wire. `obfsConn.Read` reads the full obfuscated frame into `readBuf`, but only copies up to `len(connectResp)` (256) bytes into the caller's buffer, buffering the rest in `readRest`. The client forwards a truncated 256-byte reply to the local application, producing a malformed SOCKS5 response.  
**Remediation:** Use a `io.ReadFull` loop or increase the buffer to at least `262` bytes, ideally `512` to leave headroom.

---

### P1-6 `obfsConn` missing `CloseWrite` — half-close not propagated
**File:** `pkg/obfs/conn.go`  
**Impact:** The `proxy` helper in `internal/socks5/request.go` attempts `tcpConn.CloseWrite()` to signal EOF to the peer. `obfsConn` does not implement `closeWriter`, so when a tunneled TCP stream finishes, the FIN is never forwarded through the obfuscation layer. The peer hangs waiting for more data until the idle timeout fires.  
**Remediation:** Implement `CloseWrite()` on `obfs.conn` by sending a distinguished zero-length payload frame (or a dedicated close frame) that the remote `obfsConn` translates back into `CloseWrite()` on its underlying TCP connection.

---

### P1-7 `AddUser` / `RemoveUser` bypass `userstore` when `UsersFile` is active
**File:** `pkg/s5server/server.go:124-158`  
**Impact:** `AddUser` casts `credStore.store` to `socks5.StaticCredentials`. When `UsersFile` is configured, the underlying store is `userstore.CredentialAdapter`, so `AddUser` returns an error. There is no programmatic API to add/remove users when `UsersFile` mode is enabled, forcing operators to rewrite the JSON file manually.  
**Remediation:** Expose `AddUser` / `RemoveUser` on `userstore.Store` and forward calls from `s5server.Server` regardless of backend.

---

## P2 — Medium

### P2-1 `StartPeriodicFlush` cannot be restarted after `StopPeriodicFlush`
**File:** `internal/userstore/store.go:202-222`  
**Code:**
```go
s.flushOnce.Do(func() { ... })
```
**Impact:** `sync.Once` guarantees one execution per instance lifetime. If the server is stopped and later re-started (e.g. in an embedded SDK scenario), the flush goroutine never respawns.  
**Remediation:** Replace `flushOnce` with an `atomic.Bool` or explicit goroutine lifecycle management.

---

### P2-2 Hot-reload does not update `ReadTimeout` / `WriteTimeout`
**File:** `cmd/s5core/main.go:143-173`  
**Impact:** README claims that `READ_TIMEOUT` and `WRITE_TIMEOUT` are hot-reloadable, but `setupHotReload` only calls `UpdateWhitelist` and `ReloadUsers`. The `serverListener` retains the old timeout values.  
**Remediation:** Add `setTimeouts` method to `serverListener` and invoke it during SIGHUP handling.

---

### P2-3 `s5client` does not wait for active tunnels on shutdown
**File:** `cmd/s5client/main.go:93-113`  
**Impact:** On `SIGINT` the listener is closed, but existing `handleClient` goroutines continue running. The process exits immediately only when `main` returns, but `main` blocks on `listener.Accept` which errors out quickly. There is no `sync.WaitGroup` for active handlers, so in-flight connections may be forcefully reset.  
**Remediation:** Maintain a `sync.WaitGroup` of active handlers and wait on it after `listener.Close()`.

---

### P2-4 `ServeContext` accept loop ignores context cancellation
**File:** `internal/socks5/socks5.go:130-138`  
**Impact:** The `for { Accept() }` loop has no `select` on `ctx.Done()`. When the context is cancelled, the loop blocks until the *next* incoming connection arrives before it notices that the listener is closed. This adds latency to shutdown.  
**Remediation:**
```go
for {
    conn, err := l.Accept()
    if err != nil {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
            return err
        }
    }
    // ... spawn handler
}
```

---

### P2-5 `checkRouting` sends a confusing reply code
**File:** `cmd/s5client/main.go:219-230`  
**Code:**
```go
clientConn.Write([]byte{socks5Ver, socks5UserPassAuth, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
```
**Impact:** `socks5UserPassAuth` (0x02) is semantically `"connection not allowed by ruleset"` in the REP field, but the constant name is misleading and relies on an accidental value collision. Future refactoring may break this.  
**Remediation:** Introduce a named constant `replyNotAllowed = 0x02` and use it explicitly.

---

## P3 — Low

### P3-1 Non-standard PHC base64 encoding
**File:** `internal/passwordhash/passwordhash.go:32-33`  
**Impact:** `base64.RawURLEncoding` (`-` and `_`) is used instead of the PHC-standard `base64.RawStdEncoding` ( `+` and `/`). Hashes are not portable to other Argon2id implementations.  
**Remediation:** Migrate to `base64.RawStdEncoding` and provide a backward-compatibility shim.

---

### P3-2 `matchDomain` is not IDN-aware
**File:** `cmd/s5client/main.go:421-443`  
**Impact:** `strings.ToLower` on a Unicode domain name (e.g. `München.de`) may not correctly match the punycode representation used by the resolver.  
**Remediation:** Normalize with `golang.org/x/net/idna` before comparison.

---

### P3-3 Missing upper bound on `ObfsMaxPadding`
**File:** `pkg/s5server/server_core.go:124-126`  
**Impact:** `ValidateConfig` rejects negative padding but allows values like `1_000_000`, causing huge allocations in `obfsConn.Write`.  
**Remediation:** Cap `ObfsMaxPadding` to a sensible maximum (e.g. 4096).

---

### P3-4 Per-packet allocations in UDP hot paths
**Files:** `cmd/s5client/udp_client.go:113`, `internal/socks5/associate.go:296`, `internal/socks5/associate.go:333`  
**Impact:** Every UDP packet triggers `make([]byte, ...)` instead of reusing pooled buffers. Under high packet rates this increases GC pressure.  
**Remediation:** Introduce `sync.Pool`-backed buffer pools for UDP frame assembly.

---

## Summary Table

| ID | Severity | File | Title |
|----|----------|------|-------|
| P0-1 | P0 | `request.go` | `sendReply` panic on FQDN ≥ 255 bytes |
| P0-2 | P0 | `request.go` | Default dial ignores `context.Context` |
| P0-3 | P0 | `request.go` | Panic on non-TCP `target.LocalAddr()` |
| P0-4 | P0 | `server_core.go` | Global mutex serializes Argon2id verify |
| P0-5 | P0 | `server_core.go` | Unbounded fail2ban map growth |
| P0-6 | P0 | `passwordhash.go` | Argon2id parameter DoS |
| P1-1 | P1 | `server_core.go` | `metricsConn.Close` not idempotent |
| P1-2 | P1 | `server.go` + `store.go` | Traffic data loss after `ReloadUsers` |
| P1-3 | P1 | `socks5.go` | No panic recovery in handler goroutine |
| P1-4 | P1 | `request.go` | Nil `realDestAddr` after rewriter |
| P1-5 | P1 | `main.go` (client) | CONNECT reply buffer too small |
| P1-6 | P1 | `conn.go` (obfs) | Missing `CloseWrite` implementation |
| P1-7 | P1 | `server.go` | `AddUser` incompatible with `UsersFile` mode |
| P2-1 | P2 | `store.go` | `StartPeriodicFlush` not restartable |
| P2-2 | P2 | `main.go` (server) | Hot-reload ignores timeout changes |
| P2-3 | P2 | `main.go` (client) | Graceful shutdown not awaited |
| P2-4 | P2 | `socks5.go` | Accept loop ignores `ctx.Done()` |
| P2-5 | P2 | `main.go` (client) | Misleading reply constant in routing |
| P3-1 | P3 | `passwordhash.go` | Non-standard base64 in PHC |
| P3-2 | P3 | `main.go` (client) | IDN not handled in domain routing |
| P3-3 | P3 | `server_core.go` | No upper bound on `ObfsMaxPadding` |
| P3-4 | P3 | `associate.go` / `udp_client.go` | Per-packet allocations in UDP paths |
