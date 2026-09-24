# S5Core documentation

## Install and operate

| Task | Guide |
| --- | --- |
| Start a server, update it, enable WSS or persistent accounts | [Docker deployment](guides/docker.md) |
| Look up server/client variables and defaults | [Configuration reference](guides/configuration.md) |
| Manage accounts, tunnel keys and quotas | [Accounts](guides/accounts.md) |
| Inspect metrics, reload settings and shut down | [Operations](guides/operations.md) |
| Test connectivity or configure a full tunnel | [Testing and VPN helpers](guides/testing.md) |
| Embed the server in a Go application | [Architecture and SDK](guides/sdk.md) |

## Understand and measure

| Topic | Reference |
| --- | --- |
| Transports, keepalive, UDP and their limitations | [Transport guide](design/transports.md) |
| Wire format, authoritative specification | [S5Veil specification](veil-spec.md) |
| Performance results and measurement conditions | [Results](benchmarks/results.md), [latest WAN comparison](benchmarks/wan-2026-09-22/README.md), [relay yield](benchmarks/yield.md), [protocol matrix and soak](benchmarks/matrix-2026-09-22/README.md), [raw vs 2.1 vs current](benchmarks/compare-2026-09-23/README.md), [game session under loss](benchmarks/game-loss.md) |
| Rerun the raw vs versions comparison (loopback, netem, timeouts, resume) | [Benchmark pipeline](../scripts/matrix/README.md) |
| Implementation decisions | [Session state](design/session-fsm.md), [half-close](design/half-close.md), [decoy](design/decoy.md), [observability](design/observability-policy.md) |
| Deployment and migration on real paths | [Migration](field/migration.md), [stealth](field/stealth.md), [mihomo](field/mihomo.md) |
| Acceptance gates | [Gate index](gates/README.md) |
| Open work | [Known defects](fix-plan.md), [backlog](backlog.md), [MIPS client](plan/mips.md), [game sessions](plan/gaming.md) |
| Historical investigations | [Reports](reports/), [plans](plan/README.md), [archive](archive/) |

Reports, plans and archives describe the state at their recorded date. They are
not installation instructions or evidence that the current checkout is deployed.
