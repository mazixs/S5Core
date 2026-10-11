# Benchmarks

These notes report measurements for the version, setup and conditions stated
in each document. Results are evidence for those runs, not general performance
guarantees.

## Start here

- [Results and measurement conditions](results.md)
- [Performance validation and process A/B runs](performance-validation.md)
- [WAN comparison](wan-2026-09-22/README.md)
- [Protocol matrix and soak runs](matrix-2026-09-22/README.md)
- [Raw, earlier and current version comparison](compare-2026-09-23/README.md)
- [Relay yield](yield.md)

## Focused measurements

- [Game traffic under loss](game-loss.md) and [TCP timers with `0x83`](game-tuning.md)
- [Native UDP on a narrow link](mtu-native-2026-09-26.md)
- [Queueing and radio wake-up](degradation-2026-09-26.md)
- [UDP answer bursts](udp-burst-2026-09-28.md)
- [Connection setup, RC3 and RC4](connection-setup-2026-10-06.md)
- [Frame shaping](frame-shaping.md), [UDP over TCP](udp-over-tcp.md), and [WebSocket reads](ws-read.md)

## Historical runs and raw material

Dated directories retain the procedures, fixtures and supporting measurements
for their reports. Local generated runs are kept under the ignored `bench/`
workspace; use the documents here for published results. See the
[benchmark pipeline](../../scripts/matrix/README.md) to reproduce the version
comparison.
