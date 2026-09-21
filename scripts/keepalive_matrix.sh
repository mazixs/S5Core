#!/usr/bin/env bash
# Measures how long an idle tunnel survives on different paths, with and
# without keepalive. Plan task Ф4-8: the numbers in README's keepalive table
# come from this script.
#
#   ./scripts/keepalive_matrix.sh                # direct and behind nginx
#   PROXY_TIMEOUT=30s BUDGET=90s ./scripts/keepalive_matrix.sh
#
# What it cannot measure is on the same list for a reason: a CDN and a mobile
# CGNAT are properties of somebody else's network, and no local stand
# reproduces them. Those two rows of the matrix need a deployed server and a
# phone, and the README says so rather than printing a number nobody measured.
set -euo pipefail

cd "$(dirname "$0")/.."

PROXY_TIMEOUT="${PROXY_TIMEOUT:-60s}"   # nginx idle timeout to test against
BUDGET="${BUDGET:-150s}"                # how long a run stays silent
ECHO_PORT="${ECHO_PORT:-9101}"
WS_PORT="${WS_PORT:-9443}"
NGINX_PORT="${NGINX_PORT:-9444}"
SOCKS_PORT="${SOCKS_PORT:-9080}"
PSK="${PSK:-0123456789abcdef0123456789abcdef}"
# The two keepalive settings the matrix compares. The defaults are the ones
# shipped and the one that is too slow for a 60-second proxy; a smoke run
# shortens all of them together.
KA1_MIN="${KA1_MIN:-10s}"
KA1_MAX="${KA1_MAX:-20s}"
KA2="${KA2:-90s}"
# The server's own idle timeout is part of the path and, at its default of 30
# seconds, the shortest part of it. The stand raises it so that the rows
# measure the box being tested rather than s5core; the default is measured on
# purpose in its own row, by SERVER_READ_TIMEOUT=30s.
SERVER_READ_TIMEOUT="${SERVER_READ_TIMEOUT:-600s}"

work="$(mktemp -d)"
pids=()
cleanup() {
	for pid in "${pids[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	done
	docker rm -f s5-keepalive-nginx >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "Собираю бинари"
go build -o "$work/s5core" ./cmd/s5core
go build -o "$work/s5client" ./cmd/s5client
go build -o "$work/idleprobe" ./cmd/idleprobe

say "Сертификат для WS"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
	-keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1

say "Эхо-цель и сервер"
"$work/idleprobe" -echo "127.0.0.1:$ECHO_PORT" >/dev/null 2>&1 &
pids+=($!)

WS_ENABLED=true WS_ADDR="127.0.0.1:$WS_PORT" \
WS_CERT_FILE="$work/cert.pem" WS_KEY_FILE="$work/key.pem" \
OBFS_ENABLED=true OBFS_PSK="$PSK" OBFS_PORT=0 \
READ_TIMEOUT="$SERVER_READ_TIMEOUT" WRITE_TIMEOUT="$SERVER_READ_TIMEOUT" \
PROXY_PORT=0 METRICS_PORT=0 REQUIRE_AUTH=false \
LOG_LEVEL=error \
	"$work/s5core" >"$work/server.log" 2>&1 &
pids+=($!)
sleep 2

say "nginx (proxy_timeout $PROXY_TIMEOUT) в docker"
cat > "$work/nginx.conf" <<EOF
events {}
stream {
    server {
        listen $NGINX_PORT;
        proxy_timeout $PROXY_TIMEOUT;
        proxy_pass 127.0.0.1:$WS_PORT;
    }
}
EOF
docker rm -f s5-keepalive-nginx >/dev/null 2>&1 || true
docker run -d --rm --name s5-keepalive-nginx --network host \
	-v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:alpine >/dev/null
sleep 2

# run <label> <ws-port> <keepalive-min> <keepalive-max>
run() {
	local label="$1" port="$2" kmin="$3" kmax="$4"
	local client_log="$work/client-${label//\//-}.log"

	CLIENT_LISTEN_ADDR="127.0.0.1:$SOCKS_PORT" \
	SERVER_ADDR="127.0.0.1:$port" \
	WS_URL="wss://127.0.0.1:$port/ws" \
	WS_CA_FILE="$work/cert.pem" \
	OBFS_PSK="$PSK" \
	KEEPALIVE_MIN="$kmin" KEEPALIVE_MAX="$kmax" \
	LOG_LEVEL=info \
		"$work/s5client" >"$client_log" 2>&1 &
	local client_pid=$!
	pids+=("$client_pid")
	sleep 2

	if ! kill -0 "$client_pid" 2>/dev/null; then
		printf '  %-28s клиент не поднялся: %s\n' "$label" "$(tail -1 "$client_log")"
		return
	fi

	local result
	if result=$("$work/idleprobe" -socks "127.0.0.1:$SOCKS_PORT" \
		-target "127.0.0.1:$ECHO_PORT" -budget "$BUDGET" -label "$label" 2>&1); then
		printf '  %s\n' "$result"
	else
		printf '  %s\n' "$result"
		if [[ "$result" == *"setup failed"* ]]; then
			printf '    клиент: %s\n' "$(tail -2 "$client_log" | tr '\n' ' ')"
			printf '    сервер: %s\n' "$(tail -2 "$work/server.log" | tr '\n' ' ')"
			printf '    nginx:  %s\n' "$(docker logs --tail 3 s5-keepalive-nginx 2>&1 | tr '\n' ' ')"
		fi
	fi

	kill "$client_pid" 2>/dev/null || true
	wait "$client_pid" 2>/dev/null || true
	sleep 1
}

say "Матрица: простой $BUDGET, nginx рвет после $PROXY_TIMEOUT, s5core READ_TIMEOUT=$SERVER_READ_TIMEOUT"
printf '  %-28s %-8s %s\n' "путь / keepalive" "итог" "простой"
run "direct/off"              "$WS_PORT"    "0"        "0"
run "direct/$KA1_MIN-$KA1_MAX" "$WS_PORT"    "$KA1_MIN" "$KA1_MAX"
run "direct/$KA2"             "$WS_PORT"    "$KA2"     "$KA2"
run "nginx/off"               "$NGINX_PORT" "0"        "0"
run "nginx/$KA1_MIN-$KA1_MAX"  "$NGINX_PORT" "$KA1_MIN" "$KA1_MAX"
run "nginx/$KA2"              "$NGINX_PORT" "$KA2"     "$KA2"

say "Готово"
