# S5Core 2.3 audit remediation evidence

Local validation on 3 October 2026. Implementation and remaining acceptance:
[remediation plan](../../plan/v2.3-audit-fixes.md).
The [original audit](../v2.3-code-quality-audit-2026-10-03.md) and its 49
evidence files remain the historical baseline; their manifest was verified
without changing those files.

- `metadata.json`, `source-files.json`: source base, toolchain, binary hashes
  and fingerprint of the tested Go source/module files and quality gate.
  The working tree is uncommitted; this is a known patch set, not a release.
- `precommit.txt`, `quality-metrics.json`, `quality-summary.md`: complete
  quality pipeline, 926 passed tests, 0 failures, 7 existing skips,
  75.9% coverage, 12 release-target builds and real-process smoke. Windows
  tests are compiled through an execution stub; no Windows runtime is tested.
- `regressions.txt`: uncached race-enabled tests of F1-F5 boundaries,
  queue accounting, DNS candidate coverage and fixed telemetry labels.
- `http3-local.json`: eight isolated network cases, tunnel and direct
  controls, three HTTP/3 phases per mode, 48 complete phases / 144 MiB.
  Every download and upload has the expected length and no read error;
  this probe does not calculate an application-body SHA-256.
- `mtu-acceptance.py`: narrow-path fixture selector using the existing
  `scripts/matrix/mtu_stand.py`. Each run has private user, network and mount
  namespaces. The blocked-port and initial-probe-loss rules only exist in
  those namespaces. No live server/router service is modified.

The cases cover IPv4 and IPv6 with MTU 1500, MTU 1400 with filtered PTB,
blocked native UDP and exactly six initial large probe drops. Every mode
downloads 4 MiB, uploads 1 MiB, then downloads 4 MiB on the same association.
Drop-rule packet counters are retained for the initial-loss cases. After
those six losses the client completes 14 size probes and announces a limit
of 1396 bytes for IPv4 / 1398 bytes for IPv6. Blocked native ports produce
zero native application packets and zero oversize drops at the client.
The passive data queue counter records bulk-transfer drops in three cells
(5, 24 and 46 across their phases); QUIC recovers and completes the bodies.
These counters are evidence of local burst loss, not game-loss measurements
or a comparison against the previous build.

These are Linux amd64 functional checks. Transfer rates in the raw probe
output are incidental and are not an A/B performance claim. ARM runtime,
same-path WAN, real-game and browser acceptance remain open. The legacy
installed binaries' source provenance is also unresolved.

## Repeat

From the checkout containing the remediation, with Go 1.26.8, Python 3.11+,
`unshare`, `mount`, `ip`, `tc`, `nft`, `iptables` and `ip6tables` available:

```bash
./scripts/pre-commit.sh

go test -race -count=1 -v -run '^(TestOversizeDatagramsUseTCP|TestInitialSizeProbeLoss|TestAFastRefusalDoesNotSkipAReachableTailAddress|TestDNSCandidateCoverageHasABoundedPolicy|TestFailedBackupsDoNotCreateAnUnboundedSequence|TestUDPAnswerFrameLimitKeepsTheStreamSynchronized|TestDataQueueDrops|TestProbeACKQueueDrops|TestDNSPendingDrops|TestUDPDropMetricsCountOnlyFixedReasons)' ./cmd/s5client ./internal/socks5 ./pkg/nativeudp ./pkg/s5server

mkdir -p bench/audit-fixes-repeat/bin
CGO_ENABLED=0 go build -trimpath -o bench/audit-fixes-repeat/bin/s5core ./cmd/s5core
CGO_ENABLED=0 go build -trimpath -o bench/audit-fixes-repeat/bin/s5client ./cmd/s5client
(cd scripts/matrix && go build -trimpath -o ../../bench/audit-fixes-repeat/bin/mtuprobe ./mtuprobe)

unshare -Urnm -- python3 docs/reports/data-v2.3-fixes-2026-10-03/mtu-acceptance.py quic \
  --bin "$PWD/bench/audit-fixes-repeat/bin" \
  --out "$PWD/bench/audit-fixes-repeat/mtu" \
  --down 4194304 --up 1048576 --timeout 10 --budget 420
```

Existing case JSON files are resumed rather than overwritten. Use a fresh
output directory for another build. Keep temporary binaries and detailed
process logs under the ignored `bench/` directory; retain only the reviewed
evidence here. `manifest.json` gives sizes and SHA-256 hashes for this bundle.
