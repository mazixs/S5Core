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

## Understand the design

| Topic | Reference |
| --- | --- |
| Transports, keepalive, UDP and limitations | [Transport guide](design/transports.md) |
| Wire format | [S5Veil specification](veil-spec.md) |
| Implementation decisions | [Session state](design/session-fsm.md), [half-close](design/half-close.md), [decoy](design/decoy.md), [observability](design/observability-policy.md) |
| Acceptance criteria | [Gate index](gates/README.md) |

## Measure and operate

| Topic | Reference |
| --- | --- |
| Benchmark results, conditions and historical runs | [Benchmark index](benchmarks/README.md) |
| Re-run the version comparison (loopback, netem, timeouts, resume) | [Benchmark pipeline](../scripts/matrix/README.md) |
| Deployment and migration on real paths | [Migration](field/migration.md), [stealth](field/stealth.md), [UDP shapes](field/udp-shapes.md), [mihomo](field/mihomo.md) |
| Path MTU and degradation research (Russian) | [Research index](research/README.md) |

## Plan and history

| Topic | Reference |
| --- | --- |
| Open work | [Known defects](fix-plan.md), [backlog](backlog.md), [MIPS client](plan/mips.md), [game sessions](plan/gaming.md) |
| Historical investigations | [Reports](reports/), [plans](plan/README.md), [archive](archive/) |

Reports, plans and archives describe the state at their recorded date. They are
not installation instructions or evidence that the current checkout is deployed.
