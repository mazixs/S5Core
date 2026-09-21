#!/usr/bin/env bash
# Прогон бенчмарков обфускации и сравнение с сохраненной базой.
#
# Зачем отдельный скрипт: "поменял буфер, стало быстрее" без сравнения на той
# же машине - это мнение. benchstat считает разницу с учетом разброса и
# отвечает, есть ли изменение вообще.
#
#   ./scripts/bench.sh save        снять базу в bench/baseline.txt
#   ./scripts/bench.sh             снять текущие числа и сравнить с базой
#   ./scripts/bench.sh compare A B сравнить два готовых файла
#
# Переменные: BENCH (регулярное выражение бенчмарков), COUNT (число повторов),
# BENCHTIME, PKG.
set -euo pipefail

cd "$(dirname "$0")/.."

BENCH="${BENCH:-.}"
COUNT="${COUNT:-6}"
BENCHTIME="${BENCHTIME:-1s}"
PKG="${PKG:-./pkg/obfs/}"
BASELINE="bench/baseline.txt"

GREEN=$'\033[32m'
YELLOW=$'\033[33m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

ensure_benchstat() {
    if command -v benchstat >/dev/null 2>&1; then
        return
    fi
    if [ -x "$(go env GOPATH)/bin/benchstat" ]; then
        PATH="$(go env GOPATH)/bin:$PATH"
        export PATH
        return
    fi
    echo "${YELLOW}benchstat не найден, ставлю${RESET}"
    go install golang.org/x/perf/cmd/benchstat@latest
    PATH="$(go env GOPATH)/bin:$PATH"
    export PATH
}

run_bench() {
    local out="$1"
    echo "${BOLD}==> Прогон бенчмарков${RESET} (count=$COUNT, benchtime=$BENCHTIME)"
    # -run XXX: гоняются только бенчмарки, обычные тесты не мешают замеру.
    go test -run XXX -bench="$BENCH" -benchmem -count="$COUNT" -benchtime="$BENCHTIME" "$PKG" | tee "$out"
}

case "${1:-compare_with_baseline}" in
save)
    mkdir -p bench
    run_bench "$BASELINE"
    echo "${GREEN}База сохранена в $BASELINE${RESET}"
    ;;
compare)
    ensure_benchstat
    benchstat "$2" "$3"
    ;;
compare_with_baseline)
    if [ ! -f "$BASELINE" ]; then
        echo "${YELLOW}Базы нет. Сначала на чистом дереве: ./scripts/bench.sh save${RESET}"
        exit 1
    fi
    ensure_benchstat
    current="$(mktemp)"
    trap 'rm -f "$current"' EXIT
    run_bench "$current"
    echo
    echo "${BOLD}==> Сравнение с базой${RESET}"
    benchstat "$BASELINE" "$current"
    ;;
*)
    echo "Использование: $0 [save|compare A B]" >&2
    exit 2
    ;;
esac
