## CI metrics

### Tests

915 passed, 0 failed, 7 skipped in 38 packages; the packages took 217 s together.

| slowest tests | seconds |
|---|---:|
| `cmd/s5client.TestHTTPSDefaultReadTimeout` | 33.22 |
| `internal/passwordhash.TestAHashIsWrittenInTheStandardAlphabet` | 11.04 |
| `pkg/s5server.TestAReplayedFirstFlightIsAnsweredLikeGarbage` | 7.22 |
| `pkg/s5server.TestInsideTheTunnelAReplayIsAnsweredLikeGarbage` | 7.10 |
| `pkg/s5server.TestIntegration_FullSuite` | 5.32 |
| `internal/passwordhash.TestAHashFromAnotherToolStillVerifies` | 4.95 |
| `pkg/obfs.TestFramingOverheadRatio` | 4.73 |
| `pkg/transport/ws.TestNoPieceIsLargerThanTheConfiguredMaximum` | 3.31 |
| `internal/userstore.TestLoadingRespellsHashesAndKeepsThePassword` | 3.18 |
| `pkg/nativeudp.TestPaddingNeverTakesADatagramPastTheLimit` | 2.91 |

### Coverage

**75.8%** of 11109 statements (floor 74.5%).

<details><summary>by package, lowest first</summary>

| package | statements | coverage | floor |
|---|---:|---:|---:|
| `cmd/idleprobe` | 103 | 0.0% | - |
| `cmd/stealthcheck` | 40 | 0.0% | - |
| `internal/buildinfo` | 21 | 0.0% | - |
| `internal/diagnostics` | 1 | 0.0% | - |
| `internal/testcert` | 23 | 0.0% | - |
| `scripts/smoke` | 362 | 0.0% | - |
| `cmd/connlat` | 163 | 20.9% | - |
| `cmd/fpprobe` | 215 | 25.1% | - |
| `cmd/udpprobe` | 404 | 28.2% | - |
| `cmd/wirebench` | 168 | 49.4% | - |
| `cmd/s5core` | 136 | 50.7% | - |
| `cmd/httpsprobe` | 121 | 56.2% | - |
| `cmd/fpcollect` | 129 | 59.7% | - |
| `cmd/udpshape` | 671 | 70.6% | - |
| `internal/stealth` | 405 | 75.6% | - |
| `cmd/s5client` | 1253 | 76.9% | 75.0% |
| `internal/utls` | 64 | 79.7% | - |
| `internal/identity` | 158 | 81.6% | 80.0% |
| `internal/udpbuf` | 73 | 82.2% | 80.5% |
| `internal/tcptune` | 71 | 84.5% | 83.0% |
| `scripts/metrics` | 226 | 87.2% | - |
| `pkg/veil` | 390 | 87.4% | 85.5% |
| `internal/logging` | 430 | 87.9% | - |
| `pkg/s5server` | 1296 | 88.6% | 87.0% |
| `pkg/obfs` | 651 | 90.2% | 88.5% |
| `internal/socks5` | 1718 | 90.3% | 88.5% |
| `scripts/testreport` | 83 | 90.4% | - |
| `internal/userstore` | 484 | 90.7% | 89.0% |
| `pkg/nativeudp` | 413 | 91.0% | 89.5% |
| `pkg/transport/ws` | 285 | 91.6% | 90.0% |
| `internal/s5core` | 48 | 91.7% | - |
| `pkg/transport/tlsdecoy` | 157 | 92.4% | 90.5% |
| `internal/relay` | 57 | 94.7% | 93.0% |
| `internal/session` | 185 | 95.1% | 93.5% |
| `internal/passwordhash` | 80 | 97.5% | 96.0% |
| `internal/acceptretry` | 12 | 100.0% | - |
| `internal/signals` | 13 | 100.0% | - |

</details>

### Release binaries

| binary | size | budget | headroom |
|---|---:|---:|---:|
| `s5client-darwin-amd64` | 8.75 MB | 9.70 MB | 9.8% |
| `s5client-darwin-arm64` | 8.10 MB | 9.00 MB | 10.0% |
| `s5client-linux-amd64` | 8.56 MB | 9.50 MB | 9.8% |
| `s5client-linux-arm64` | 7.93 MB | 8.80 MB | 9.9% |
| `s5client-linux-mips-softfloat` | 9.31 MB | 10.30 MB | 9.6% |
| `s5client-linux-mipsle-softfloat` | 9.31 MB | 10.30 MB | 9.6% |
| `s5client-windows-amd64.exe` | 8.91 MB | 9.90 MB | 10.0% |
| `s5core-darwin-amd64` | 14.81 MB | 16.30 MB | 9.1% |
| `s5core-darwin-arm64` | 13.79 MB | 15.20 MB | 9.3% |
| `s5core-linux-amd64` | 14.36 MB | 15.90 MB | 9.7% |
| `s5core-linux-arm64` | 13.30 MB | 14.70 MB | 9.5% |
| `s5core-windows-amd64.exe` | 14.75 MB | 16.30 MB | 9.5% |
