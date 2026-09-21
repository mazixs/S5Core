#!/usr/bin/env bash
# Задача плана Ф4-10: сколько стоит UDP-over-TCP (команда 0x83) на канале с
# потерями.
#
# Команда 0x83 мультиплексирует все UDP-потоки сессии в одно TCP-соединение -
# именно это закрывает утечки WebRTC, QUIC и DNS. Цена известна качественно:
# потерянный сегмент останавливает доставку всех потоков, пока его не
# перешлют. Скрипт превращает это в числа.
#
# Стенд: три контейнера в одной docker-сети.
#
#   client (netem) --- server --- target (netem)
#
# netem висит на исходящем интерфейсе client и target, поэтому и прямой путь,
# и путь через туннель проходят ровно два участка с потерями и одинаковый RTT.
# Разница в результатах - это разница между "потерянная датаграмма просто
# пропала" и "потерянный сегмент задержал всех".
#
# Требуется docker. tc запускается внутри контейнеров (--cap-add NET_ADMIN),
# на хосте root не нужен.
#
#   ./scripts/udp_loss_matrix.sh
#   DELAY=25ms PACKETS=400 LOSSES="0 1 3" ./scripts/udp_loss_matrix.sh

set -euo pipefail
cd "$(dirname "$0")/.."

DELAY="${DELAY:-25ms}"          # односторонняя задержка на каждом участке
PACKETS="${PACKETS:-400}"
INTERVAL="${INTERVAL:-20ms}"
SIZE="${SIZE:-60}"              # размер DNS-запроса
LOSSES="${LOSSES:-0 1 3}"
NET="${NET:-s5netem}"
IMAGE="${IMAGE:-s5-netem:local}"
PSK="${PSK:-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH}"
OUT="${OUT:-/tmp/s5-udp-netem}"

bold() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f s5-client s5-server s5-target >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

bold "Собираю бинари"
mkdir -p "$OUT/bin"
CGO_ENABLED=0 go build -o "$OUT/bin/s5core" ./cmd/s5core
CGO_ENABLED=0 go build -o "$OUT/bin/s5client" ./cmd/s5client
CGO_ENABLED=0 go build -o "$OUT/bin/udpprobe" ./cmd/udpprobe

bold "Образ с tc"
printf 'FROM alpine:3.21\nRUN apk add --no-cache iproute2\n' > "$OUT/Dockerfile"
docker build -q -t "$IMAGE" "$OUT" >/dev/null

cleanup
docker network create "$NET" >/dev/null

bold "Контейнеры"
docker run -d --name s5-target --network "$NET" --cap-add NET_ADMIN \
  -v "$OUT/bin:/bin/s5:ro" "$IMAGE" /bin/s5/udpprobe -echo 0.0.0.0:9999 >/dev/null

docker run -d --name s5-server --network "$NET" \
  -e REQUIRE_AUTH=false -e PROXY_LISTEN_IP=0.0.0.0 -e PROXY_PORT=1080 \
  -e OBFS_ENABLED=true -e OBFS_PORT=1443 -e OBFS_PSK="$PSK" -e LOG_LEVEL=warn \
  -v "$OUT/bin:/bin/s5:ro" "$IMAGE" /bin/s5/s5core >/dev/null

docker run -d --name s5-client --network "$NET" --cap-add NET_ADMIN \
  -e SERVER_ADDR=s5-server:1443 -e OBFS_PSK="$PSK" -e CLIENT_LISTEN_ADDR=0.0.0.0:1080 \
  -e LOG_LEVEL=warn -v "$OUT/bin:/bin/s5:ro" "$IMAGE" /bin/s5/s5client >/dev/null

sleep 3
for c in s5-target s5-server s5-client; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$c")" != "true" ]; then
    echo "контейнер $c не поднялся:"; docker logs "$c" | tail -20; exit 1
  fi
done

netem() { # netem <контейнер> <loss%>
  docker exec "$1" tc qdisc del dev eth0 root >/dev/null 2>&1 || true
  if [ "$2" = "0" ]; then
    docker exec "$1" tc qdisc add dev eth0 root netem delay "$DELAY"
  else
    docker exec "$1" tc qdisc add dev eth0 root netem delay "$DELAY" loss "${2}%"
  fi
}

probe() { # probe <label> <кол-во> <интервал> <доп. аргументы>
  docker exec s5-client /bin/s5/udpprobe \
    -target s5-target:9999 -n "$2" -interval "$3" -size "$SIZE" \
    -label "$1" "${@:4}"
}

# Два профиля, потому что 0x83 бьет по ним по-разному. Отдельные запросы
# (DNS) страдают от задержки повторной передачи каждый сам по себе; поток
# страдает от того, что задержка одного сегмента задерживает и все, что
# пришло после него.
DNS_PACKETS="${DNS_PACKETS:-40}"
DNS_INTERVAL="${DNS_INTERVAL:-200ms}"

bold "Матрица: задержка $DELAY на участок, пакеты по $SIZE байт"
printf '  %s\n' "потери  профиль/путь"
for loss in $LOSSES; do
  netem s5-client "$loss"
  netem s5-target "$loss"
  # Прогрев: первое обращение через туннель поднимает TCP-соединение и
  # рукопожатие, и его стоимость не относится к измеряемому.
  probe warmup 5 20ms -socks 127.0.0.1:1080 >/dev/null 2>&1 || true
  printf '  %s%%\t%s\n' "$loss" "$(probe "dns/direct   " "$DNS_PACKETS" "$DNS_INTERVAL")"
  printf '  %s%%\t%s\n' "$loss" "$(probe "dns/tunnel   " "$DNS_PACKETS" "$DNS_INTERVAL" -socks 127.0.0.1:1080)"
  printf '  %s%%\t%s\n' "$loss" "$(probe "stream/direct" "$PACKETS" "$INTERVAL")"
  printf '  %s%%\t%s\n' "$loss" "$(probe "stream/tunnel" "$PACKETS" "$INTERVAL" -socks 127.0.0.1:1080)"
done

bold "Готово"
