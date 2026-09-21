#!/usr/bin/env bash
# Шлюз G4 плана: сколько кругов стоит установка соединения и что из них мог
# бы сэкономить 0-RTT в первом кадре.
#
# Правило выбора на шлюзе опирается на разложение наблюдаемых 0,31 с до
# первого байта. Секунды зависят от канала, а количество кругов - нет: это
# свойство протокола. Поэтому стенд задает известный симметричный RTT и
# меряет установку в его единицах.
#
# Стенд: три контейнера, netem на исходящем интерфейсе каждого, так что
# круговой путь между любой парой равен 2 x DELAY.
#
#   client (netem) --- server (netem) --- target (netem)
#
# Замеряются четыре пути:
#   direct       - зонд прямо в цель, контрольное измерение
#   socks        - через s5core без обфускации (голый SOCKS5 по TCP)
#   obfs         - через s5client -> обфусцированный слушатель s5core
#   wss          - через s5client -> WebSocket поверх TLS
#
#   ./scripts/conn_latency.sh
#   DELAY=25ms RUNS=30 ./scripts/conn_latency.sh

set -euo pipefail
cd "$(dirname "$0")/.."

DELAY="${DELAY:-25ms}"          # односторонняя задержка на каждом участке
RUNS="${RUNS:-20}"
NET="${NET:-s5lat}"
IMAGE="${IMAGE:-s5-netem:local}"
PSK="${PSK:-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH}"
OUT="${OUT:-/tmp/s5-conn-latency}"

bold() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f lat-client lat-wsclient lat-server lat-target >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

bold "Собираю бинари"
mkdir -p "$OUT/bin"
CGO_ENABLED=0 go build -o "$OUT/bin/s5core" ./cmd/s5core
CGO_ENABLED=0 go build -o "$OUT/bin/s5client" ./cmd/s5client
CGO_ENABLED=0 go build -o "$OUT/bin/connlat" ./cmd/connlat

bold "Сертификат для WS"
if [ ! -f "$OUT/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" \
    -days 2 -subj "/CN=lat-server" -addext "subjectAltName=DNS:lat-server" >/dev/null 2>&1
fi

bold "Образ с tc"
printf 'FROM alpine:3.21\nRUN apk add --no-cache iproute2\n' > "$OUT/Dockerfile"
docker build -q -t "$IMAGE" "$OUT" >/dev/null

cleanup
docker network create "$NET" >/dev/null

bold "Контейнеры"
docker run -d --name lat-target --network "$NET" --cap-add NET_ADMIN \
  -v "$OUT/bin:/bin/s5:ro" "$IMAGE" /bin/s5/connlat -listen 0.0.0.0:9100 >/dev/null

docker run -d --name lat-server --network "$NET" --cap-add NET_ADMIN \
  -e REQUIRE_AUTH=false -e PROXY_LISTEN_IP=0.0.0.0 -e PROXY_PORT=1080 \
  -e OBFS_ENABLED=true -e OBFS_PORT=1443 -e OBFS_PSK="$PSK" \
  -e WS_ENABLED=true -e WS_ADDR=0.0.0.0:8443 -e WS_PATH=/ws \
  -e WS_CERT_FILE=/etc/s5/cert.pem -e WS_KEY_FILE=/etc/s5/key.pem \
  -e LOG_LEVEL=warn \
  -v "$OUT/bin:/bin/s5:ro" -v "$OUT:/etc/s5:ro" "$IMAGE" /bin/s5/s5core >/dev/null

docker run -d --name lat-client --network "$NET" --cap-add NET_ADMIN \
  -e SERVER_ADDR=lat-server:1443 -e OBFS_PSK="$PSK" -e CLIENT_LISTEN_ADDR=0.0.0.0:1080 \
  -e LOG_LEVEL=warn -v "$OUT/bin:/bin/s5:ro" "$IMAGE" /bin/s5/s5client >/dev/null

# Второй клиент живет в сетевом пространстве первого: тот же netem, тот же
# localhost. Иначе зонд шел бы до него через лишний участок с задержкой.
docker run -d --name lat-wsclient --network "container:lat-client" \
  -e SERVER_ADDR=lat-server:1443 -e OBFS_PSK="$PSK" -e CLIENT_LISTEN_ADDR=127.0.0.1:1081 \
  -e WS_URL="wss://lat-server:8443/ws" -e WS_CA_FILE=/etc/s5/cert.pem \
  -e LOG_LEVEL=warn -v "$OUT/bin:/bin/s5:ro" -v "$OUT:/etc/s5:ro" "$IMAGE" /bin/s5/s5client >/dev/null

sleep 3
for c in lat-target lat-server lat-client lat-wsclient; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" != "true" ]; then
    echo "контейнер $c не поднялся:"; docker logs "$c" 2>&1 | tail -20; exit 1
  fi
done

netem() { # netem <контейнер>
  docker exec "$1" tc qdisc del dev eth0 root >/dev/null 2>&1 || true
  docker exec "$1" tc qdisc add dev eth0 root netem delay "$DELAY"
}
netem lat-client
netem lat-server
netem lat-target

RTT=$(( 2 * ${DELAY%ms} ))ms

probe() { # probe <label> <доп. аргументы>
  docker exec lat-client /bin/s5/connlat \
    -target lat-target:9100 -n "$RUNS" -rtt "$RTT" -label "$1" "${@:2}"
}

bold "Установка соединения при RTT $RTT между любой парой узлов"
status=0
probe "direct" || status=1
probe "socks " -socks lat-server:1080 || status=1
probe "obfs  " -socks 127.0.0.1:1080 || status=1
probe "wss   " -socks 127.0.0.1:1081 || status=1

if (( status != 0 )); then
  echo "Измерение не прошло: один или несколько путей завершились с ошибкой" >&2
  exit "$status"
fi
bold "Готово"
