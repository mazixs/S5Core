# Authentication & Multi-Account Management

S5Core utilizes a high-performance, lock-free JSON user store capable of tracking per-user traffic limits without impacting the hot path.

By defining an optional `USERS_FILE`, you can enable multi-account support with expiration dates and traffic quotas. If no file is provided, `PROXY_USER`/`PROXY_PASSWORD` fill the same store with a single account.

> **One mechanism, not two.** `PROXY_USER` used to be a plain map of passwords
> beside the store, which meant Argon2id, quotas, expiry dates and roles
> existed for a deployment with a file and not for one without it, and
> `AddUser` did something different depending on which one you had. Since plan
> task Ф6-3 there is one store either way: without a file it simply has no
> file, so it starts empty and `AddUser` fills it. What `USERS_FILE` still adds
> is persistence and the tunnel member directory - keys cannot be resolved from
> accounts that are not written down.

> **The KDF runs once per password, not once per connection.** SOCKS5
> authenticates on every TCP connection, and a browser opens six to ten of them
> per page, so running Argon2id (64 MiB, three passes) per login used to cost
> 261 ms to first byte and +514 MiB of RSS for a single page - and 18.7 GiB of
> peak RSS at 100 connections per second. The store now verifies a password
> with the full KDF once, then remembers a keyed hash of it (HMAC under a key
> generated at startup, never persisted) and compares that in constant time.
> Concurrent logins with the same credentials collapse into a single KDF run,
> which is the case that matters: a cold cache and ten simultaneous
> connections.
>
> | Load | Legacy `PROXY_USER` | `USERS_FILE` + Argon2id |
> |---|---|---|
> | One burst of 10 connections (one browser page) | 0.5 ms to first byte | 0.4 ms to first byte |
> | 100 connections/s for 10 s | 0.3 ms p50, +5 MiB RSS | 0.3 ms p50, +1 MiB RSS |
>
> An entry records the exact hash it was verified against, so changing a
> password in `users.json` invalidates it with no cache to clear by hand, and a
> wrong password is answered from the entry too - guessing cannot make the
> server spend 64 MiB per attempt. Method and full numbers:
> [docs/benchmarks/argon2-cost.md](../benchmarks/argon2-cost.md). What stays expensive by design is
> the first login of each password after start: one 110 ms KDF run, which is
> where a strong KDF belongs.

### Example `users.json`

```json
{
  "users": [
    {
      "id": "u-001",
      "username": "premium_user",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "comment": "100GB limit, expires in 2027",
      "valid_until": "2027-01-01T00:00:00Z",
      "traffic_limit_bytes": 107374182400,
      "traffic_used_bytes": 0,
      "enabled": true
    },
    {
      "id": "u-002",
      "username": "unlimited_user",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "tunnel_key": "9Qm2t0s0cW1Zr7Yb3kF6uH8aJ4nP1xV5dS7gK0lE2oM=",
      "enabled": true
    },
    {
      "id": "u-003",
      "username": "noc",
      "password_hash": "$argon2id$v=19$m=65536,t=3,p=1$...",
      "tunnel_key": "Zr7Yb3kF6uH8aJ4nP1xV5dS7gK0lE2oM9Qm2t0s0cW1=",
      "role": "operator",
      "enabled": true
    }
  ]
}
```

> **Security:** Passwords are stored as **Argon2id** hashes. Plaintext `password` fields are supported for backward compatibility but are automatically migrated to hashes on the first successful login.

> **Hash portability:** the hash is a standard PHC string - `base64` with the
> standard alphabet and no padding - so any other Argon2id implementation can
> verify it. Builds before this one used the URL-safe alphabet (`-_` instead of
> `+/`); such a file is rewritten in the standard spelling when it is read, with
> a log line naming the accounts. Nothing about a password changes: the salt and
> the hash are the same bytes, only spelled differently, and both spellings keep
> verifying.

> **A hash is checked when the file is read, not when someone logs in.**
> Argon2id answers some malformed parameters with a panic rather than an error
> - no rounds, no parallelism, an empty tag - and a negative one used to ask
> the allocator for terabytes, so a hash S5Core could not check would have
> taken the process down on whichever connection first tried to use it. Such a
> file is refused whole, at startup or at the `SIGHUP` that introduced it, with
> the account named in the error; a reload that fails leaves the accounts
> already serving traffic exactly as they were.

> **A migration can be dropped, and that is the point.** Hashing a legacy
> plaintext password happens with the store unlocked, because 110 ms with the
> lock held would stall every other connection - and `SIGHUP` can re-read the
> file during those 110 ms. If the account has meanwhile been removed, been
> given a hash by something else, or been given a different plaintext, the hash
> is discarded with a log line instead of being written: the operator's edit
> wins, and the next login migrates from whatever the file says by then.

> **`tunnel_key`** is optional and independent of the password: 32 random bytes
> in base64 (`openssl rand -base64 32`), never derived from anything the user
> chose. An account that has one is recognised by the obfuscated transport
> before the SOCKS5 handshake and is never asked for a password there; an
> account without one behaves exactly as before. Give the same value to that
> user's client as `OBFS_MEMBER_KEY`. Deleting the key, or the account, stops
> it resolving at the next `SIGHUP`.

#### Roles

`role` says what an account may do besides passing traffic. It is checked by
the SDK and by whatever control panel sits on top of it, never on the
connection path - a role has no effect on whether bytes flow, which is the
policy's job (`enabled`, `valid_until`, `traffic_limit_bytes`).

| Role | Connect | View accounts | Manage the server | Manage accounts |
|---|---|---|---|---|
| `user` (default, and any account with no `role`) | yes | - | - | - |
| `operator` | yes | yes | yes | - |
| `admin` | yes | yes | yes | yes |

"Manage the server" is the client whitelist, the timeouts and reloading the
account file; "manage accounts" is creating, removing and re-roling them. An
operator cannot promote itself, because promoting is managing accounts. A
`role` that is not one of the three is refused when the file is read, rather
than resolved to something convenient later.

The roles are enforced on `Server.As(username)`, not on `Server` itself - see
[SDK](sdk.md#acting-on-behalf-of-an-account).

#### Migration of an existing `users.json`

An account file written before tunnel keys existed is migrated when it is
read: every account without a `tunnel_key` is given one - 32 bytes from
`crypto/rand`, not derived from the password - and the file is written back,
so the keys survive a restart. Nothing else about the accounts changes, and no
client is affected until you hand it a key: an account whose client does not
have one keeps authenticating with its password over the shared account.

The server logs a warning naming the accounts it changed and where to read
their keys. It does not log the keys themselves - a log line is shipped,
rotated and read by people who are not the account's owner. Read them from
`users.json` and give each one to its client as `OBFS_MEMBER_KEY`.

A `SIGHUP` reload migrates in memory only and does not rewrite the file: you
have just edited it, and a signal handler does not get to write over that.

#### Quotas and validity dates during a session

A quota, a `valid_until` date and the `enabled` flag are checked at login and
again while the session runs. The relay re-checks them on the boundary where it
already publishes its traffic counter, so a session that runs out of quota in
the middle of a transfer ends within 64 KiB of the byte that exhausted it, and
does not have to wait for the client to reconnect.

The check counts the bytes that have not been written to `users.json` yet, so it
is not affected by `TRAFFIC_FLUSH_INTERVAL`. An account disabled or removed by
`SIGHUP` also stops transferring within the same 64 KiB, rather than keeping its
current sessions until they end on their own.

UDP is metered the same way, in both modes - the RFC 1928 association and the
`0x83` tunnel. An association asks the account on the same 64 KiB boundary, and
also whenever a second has passed since it last asked, because an association
that moves 60 bytes per query would otherwise reach the byte boundary hours
later and keep running on an account that has expired in the meantime. An
association that may no longer transfer ends: unlike a stream, a datagram has
no exchange in flight worth draining, so there is no grace period here.

**What counts against a quota:** the payload, in both directions, counted once
each. The SOCKS5 UDP header this server adds and strips does not count, and
neither does the two-byte length prefix of the `0x83` tunnel. A header is 10
bytes for an IPv4 destination, 22 for IPv6 and 7 plus the name for an FQDN, so
billing it would make the same transfer cost different amounts of quota
depending on how the client spelled the address.

> **Hot Reloading:** Send `SIGHUP` to the S5Core process to reload `users.json` on the fly without dropping connections! Traffic metrics are preserved and merged during reload. The same signal re-reads the log level (`LOG_LEVEL_FILE`, falling back to `LOG_LEVEL`).
>
> **Diagnostics on a live process:** `SIGUSR1` toggles `debug` on and off, on both `s5core` and `s5client`, with no configuration prepared in advance. An unreadable or misspelled level is reported and the previous level is kept - a reload must never silently turn diagnostics off in the middle of an incident.
>
> **On Windows** neither signal exists: there is no `SIGUSR1` at all, and nothing delivers `SIGHUP`. Both binaries build and run there, and both stop cleanly on Ctrl-C, but the configuration they started with is the configuration they keep - reloading means restarting the process, and the log level is whatever `LOG_LEVEL` or `LOG_LEVEL_FILE` said at startup. The signal names live in `internal/signals`, one file per platform, so this is a stated difference rather than a build that fails at release time.

[Documentation index](../README.md) · [Project home](../../README.md)
