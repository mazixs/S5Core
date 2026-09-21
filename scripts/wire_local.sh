#!/usr/bin/env bash
# Локальный стенд для замера полосы, откалиброванный по боевому каналу.
#
# Зачем. Числа с loopback не сравнимы с боевыми ни в какую сторону: там нет ни
# RTT, ни ограничения полосы, поэтому туннель на loopback упирается в шифр, а в
# поле - в окно TCP. Этот стенд ставит между клиентом и сервером те же RTT и
# полосу, что измерены на боевом VPS (docs/gates/README.md, вердикт G1), и тогда
# локальный прогон годится для оценки прогресса и регрессии без VPS.
#
# Калибровка: параметры подбираются так, чтобы ПРЯМОЙ замер (мимо туннеля) сошелся
# с прямым замером на боевом канале. Дефолты ниже - результат такой подгонки,
# числа и способ проверки в docs/benchmarks/local-bandwidth.md.
#
#   ./scripts/wire_local.sh                # прогон с дефолтами
#   RTT_MS=43 RATE=600mbit ./scripts/wire_local.sh
#   KEEP=1 ./scripts/wire_local.sh         # не убирать контейнеры после прогона
#
# Требуется docker с возможностью NET_ADMIN (эмуляция канала ставится внутри
# контейнеров, root на хосте не нужен).

set -euo pipefail

cd "$(dirname "$0")/.."

NET=${NET:-s5bench}
IMAGE=${IMAGE:-s5core:bench}
RTT_MS=${RTT_MS:-43}          # круговая задержка канала клиент-сервер, мс
RATE=${RATE:-390mbit}         # полоса канала; дефолт подобран под боевой канал
LOSS=${LOSS:-0.02}            # потери в процентах
REPS=${REPS:-3}
SIZE=${SIZE:-$((256 * 1024 * 1024))}
DIRS=${DIRS:-"down up"}
OUT=${OUT:-}
KEEP=${KEEP:-0}

USER_NAME=bench
PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
PSK=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)

say() { printf '\033[1m%s\033[0m\n' "$*"; }

cleanup() {
  [ "$KEEP" = "1" ] && { say "контейнеры оставлены: ${NET}-target ${NET}-server ${NET}-client"; return; }
  docker rm -f "${NET}-client" "${NET}-server" "${NET}-target" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "==> Сборка инструментов"
CGO_ENABLED=0 GOOS=linux go build -o bin/wirebench ./cmd/wirebench
CGO_ENABLED=0 GOOS=linux go build -o bin/s5client ./cmd/s5client
CGO_ENABLED=0 GOOS=linux go build -o bin/s5core ./cmd/s5core

docker image inspect "$IMAGE" >/dev/null 2>&1 || {
  say "==> Образ $IMAGE отсутствует, собираю"
  docker build -q -t "$IMAGE" . >/dev/null
}

cleanup
docker network create "$NET" >/dev/null

# Один образ на все три роли: нужен только shell, iproute2 и наши бинари.
BASE=${BASE:-alpine:3.20}
docker pull -q "$BASE" >/dev/null

run_node() { # имя, команда
  docker run -d --name "$1" --network "$NET" --cap-add NET_ADMIN \
    -v "$PWD/bin:/bin5:ro" "$BASE" sh -c "$2" >/dev/null
}

say "==> Поднимаю узлы"
run_node "${NET}-target" '/bin5/wirebench -serve :5301'

# Сервер: обфускация на 47832, SOCKS5 открытым текстом на 2190 для контроля.
run_node "${NET}-server" "PROXY_PORT=2190 PROXY_LISTEN_IP=0.0.0.0 REQUIRE_AUTH=true \
  PROXY_USER=$USER_NAME PROXY_PASSWORD=$PASSWORD \
  OBFS_ENABLED=true OBFS_PORT=47832 OBFS_PSK=$PSK OBFS_NODE_ID=localbench \
  METRICS_BIND_ADDR=127.0.0.1 LOG_LEVEL=warn /bin5/s5core"

run_node "${NET}-client" "CLIENT_LISTEN_ADDR=0.0.0.0:1080 SERVER_ADDR=${NET}-server:47832 \
  PROXY_USER=$USER_NAME PROXY_PASS=$PASSWORD OBFS_PSK=$PSK OBFS_NODE_ID=localbench \
  TRANSPORT=obfs OBFS_FORMAT=v1 TIMEZONE_CHECK=false LOG_LEVEL=warn /bin5/s5client"

sleep 2

# Эмуляция канала повторяет боевую топологию, а не симметричную лабораторную:
# в поле между клиентом и сервером лежит канал с RTT и полосой, а между сервером
# и целью - ничего (цель стоит рядом с сервером). Поэтому вся задержка ставится
# на исходящий трафик клиента: любой путь клиента получает круговую RTT_MS, а
# путь сервер-цель остается быстрым. Полоса ограничивается с обеих сторон, иначе
# ограничено только одно направление.
netem_loss=""
[ "$LOSS" != "0" ] && netem_loss="loss ${LOSS}%"

# limit - очередь netem в пакетах. На RTT_MS и RATE в полете держится
# RATE*RTT/8/1500 пакетов; при дефолтном лимите в 1000 они бы дропались, и
# замерялись бы потери эмулятора, а не канал.
rate_bits=$(python3 -c "s='$RATE'.lower(); n=float(''.join(c for c in s if c.isdigit() or c=='.')); print(int(n*(1e9 if 'g' in s else 1e6 if 'm' in s else 1e3 if 'k' in s else 1)))")
limit=$(python3 -c "import math; print(max(10000, math.ceil($rate_bits*$RTT_MS/1000/8/1500*4)))")

say "==> Эмуляция канала: RTT ${RTT_MS} мс, полоса ${RATE}${LOSS:+, потери ${LOSS}%}"
docker exec "${NET}-client" sh -c "apk add -q iproute2 && \
  tc qdisc add dev eth0 root netem delay ${RTT_MS}ms rate $RATE limit $limit $netem_loss" >/dev/null
for node in "${NET}-server" "${NET}-target"; do
  docker exec "$node" sh -c "apk add -q iproute2 && \
    tc qdisc add dev eth0 root netem rate $RATE limit $limit" >/dev/null
done

wb() { docker exec "${NET}-client" /bin5/wirebench "$@"; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; cleanup' EXIT

say "==> Прогон: $REPS повторов, $(python3 -c "print($SIZE//1048576)") МиБ на замер"
for dir in $DIRS; do
  for rep in $(seq 1 "$REPS"); do
    wb -url "http://${NET}-target:5301" -dir "$dir" -n "$SIZE" -label "direct-$dir" \
      | tee -a "$TMP/raw.txt"
    wb -url "http://${NET}-target:5301" -socks "${NET}-server:2190" -user "$USER_NAME" -pass "$PASSWORD" \
      -dir "$dir" -n "$SIZE" -label "plain-$dir" | tee -a "$TMP/raw.txt"
    wb -url "http://${NET}-target:5301" -socks "127.0.0.1:1080" -user "$USER_NAME" -pass "$PASSWORD" \
      -dir "$dir" -n "$SIZE" -label "obfs-$dir" | tee -a "$TMP/raw.txt"
  done
done

say "==> Медианы"
python3 - "$TMP/raw.txt" <<'PY'
import re, sys, statistics
from collections import defaultdict
vals = defaultdict(list)
for line in open(sys.argv[1]):
    m = re.match(r"(\S+)\s+([\d.]+) Mi?B/s", line.strip())
    if m:
        vals[m.group(1)].append(float(m.group(2)))
base = {}
for name in ("direct-down", "direct-up"):
    if vals.get(name):
        base[name.split("-")[1]] = statistics.median(vals[name])
print(f"{'путь':14s} {'медиана МиБ/с':>14s} {'Мбит/с':>10s} {'доля канала':>13s}")
for name in sorted(vals):
    med = statistics.median(vals[name])
    direction = name.split("-")[1]
    share = f"{100*med/base[direction]:.1f}%" if direction in base and base[direction] else "-"
    print(f"{name:14s} {med:>14.2f} {med*2**20*8/1e6:>10.1f} {share:>13s}")
PY

[ -n "$OUT" ] && cp "$TMP/raw.txt" "$OUT" && say "сырые строки: $OUT"
