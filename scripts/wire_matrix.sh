#!/usr/bin/env bash
# wire_matrix.sh - what fraction of the link the tunnel delivers (plan task
# Ф2-1, gate G1).
#
# The link is not a constant: a single pair of numbers taken minutes apart
# compares two moments as much as two paths. So every variant is measured
# REPS times, interleaved - link, plain, obfs, link, plain, obfs - and the
# summary is the median of each column. Interleaving reduces drift bias but
# does not guarantee equal conditions; keep the raw samples and their spread.
#
# Needs: cmd/wirebench running with -serve on the far side, and a local
# s5client for the obfuscated column.
#
#   WIRE_DIRECT=http://vps:5301 \
#   WIRE_INNER=http://172.17.0.1:5301 \
#   WIRE_SOCKS_PLAIN=vps:2190 WIRE_USER=bench WIRE_PASS=... \
#   WIRE_SOCKS_OBFS=127.0.0.1:11080 \
#   ./scripts/wire_matrix.sh
#
# WIRE_INNER is the same far end as seen from inside the proxy: a SOCKS5
# server reaches it over its own loopback, not over the link.
set -euo pipefail

REPS="${REPS:-5}"
SIZE="${SIZE:-256MB}"
OUT="${OUT:-bench/wire}"
DIRS="${DIRS:-down up}"

: "${WIRE_DIRECT:?set WIRE_DIRECT, e.g. http://vps:5301}"
: "${WIRE_INNER:=$WIRE_DIRECT}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${WIREBENCH:-$root/bin/wirebench}"
if [ ! -x "$bin" ]; then
    mkdir -p "$(dirname "$bin")"
    (cd "$root" && go build -o "$bin" ./cmd/wirebench)
fi
mkdir -p "$OUT"
raw="$OUT/raw.txt"
: > "$raw"

run() { # name direction extra-args...
    local name="$1" dir="$2"; shift 2
    local line
    line="$("$bin" -n "$SIZE" -dir "$dir" -label "$name" "$@")"
    echo "$line"
    # name<TAB>direction<TAB>MiB/s. Old wirebench labeled binary MiB as MB.
    printf '%s\t%s\t%s\n' "$name" "$dir" "$(awk '{for(i=1;i<=NF;i++) if($i=="MiB/s" || $i=="MB/s"){print $(i-1); exit}}' <<<"$line")" >> "$raw"
}

for dir in $DIRS; do
    for ((i = 1; i <= REPS; i++)); do
        run link "$dir" -url "$WIRE_DIRECT"
        if [ -n "${WIRE_SOCKS_PLAIN:-}" ]; then
            run plain "$dir" -url "$WIRE_INNER" -socks "$WIRE_SOCKS_PLAIN" \
                -user "${WIRE_USER:-}" -pass "${WIRE_PASS:-}"
        fi
        if [ -n "${WIRE_SOCKS_OBFS:-}" ]; then
            run obfs "$dir" -url "$WIRE_INNER" -socks "$WIRE_SOCKS_OBFS"
        fi
    done
done

echo
echo "медианы по $REPS повторам, $SIZE на соединение:"
python3 - "$raw" <<'PY'
import sys, statistics, collections
rows = collections.defaultdict(list)
for line in open(sys.argv[1]):
    name, direction, rate = line.split('\t')
    rows[(direction, name)].append(float(rate))
for direction in ('down', 'up'):
    link = rows.get((direction, 'link'))
    if not link:
        continue
    base = statistics.median(link)
    print(f"  {direction}:")
    for name in ('link', 'plain', 'obfs'):
        vals = rows.get((direction, name))
        if not vals:
            continue
        med = statistics.median(vals)
        share = f"{med / base * 100:5.1f}% канала" if name != 'link' else "  base"
        print(f"    {name:<6} {med:7.2f} MiB/s ({med * 2**20 * 8 / 1e6:7.1f} Mbit/s)  {share}"
              f"   разброс {min(vals):.2f}..{max(vals):.2f}")
PY
