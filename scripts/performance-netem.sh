#!/usr/bin/env bash
# Only a fresh user/network namespace and fixed tunnel ports are changed.
set -euo pipefail
if [[ ${1:-} != --inside ]]; then
    [[ $# -ge 4 ]] || { echo "usage: $0 RTT_MS LOSS_PERCENT RATE_MBIT COMMAND [ARGS...]" >&2; exit 2; }
    export S5_NETEM_PARENT_NS
    S5_NETEM_PARENT_NS=$(readlink /proc/self/ns/net)
    exec unshare --user --map-root-user --net "$0" --inside "$@"
fi
shift
if [[ -z ${S5_NETEM_PARENT_NS:-} || $(readlink /proc/self/ns/net) == "$S5_NETEM_PARENT_NS" ]]; then
    echo 'Refusing netem outside a fresh network namespace' >&2
    exit 2
fi
rtt_ms=$1 loss_pct=$2 rate_mbit=$3
shift 3
[[ $rtt_ms =~ ^[0-9]+$ && $loss_pct =~ ^[0-9]+([.][0-9]+)?$ && $rate_mbit =~ ^[0-9]+$ ]] || exit 2
half_ms=$(awk -v rtt="$rtt_ms" 'BEGIN {print rtt/2}')
ip link set lo up mtu "${S5_NETEM_MTU:-1500}"
tc qdisc add dev lo root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
tc qdisc add dev lo parent 1:3 handle 30: netem delay "${half_ms}ms" loss "${loss_pct}%" rate "${rate_mbit}mbit" limit 100000
for port in 41443 41444; do
    for direction in sport dport; do
        tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff match ip "$direction" "$port" 0xffff flowid 1:3
    done
done
export S5_PERF_OBFS_ADDR=127.0.0.1:41443 S5_PERF_WS_ADDR=127.0.0.1:41444
printf 'isolated netem: RTT=%sms loss=%s%% rate=%sMbit/s; origin/control bypass netem\n' "$rtt_ms" "$loss_pct" "$rate_mbit"
cat /proc/net/snmp
set +e
"$@"
result=$?
set -e
tc -s qdisc show dev lo
cat /proc/net/snmp
exit "$result"
