#!/usr/bin/env bash
#
# fuzz.sh - run the native Go fuzz targets of the module as one campaign.
#
#   ./scripts/fuzz.sh                    every FuzzXxx target, 5 minutes each
#   ./scripts/fuzz.sh 'PHC|socks5'       targets whose "pkg/dir.FuzzName" matches
#   FUZZ_TIME=60s FUZZ_JOBS=3 ./scripts/fuzz.sh
#
# Targets are found in the packages of the root module (go list ./...), so a
# nested module such as scripts/matrix is not picked up. Each target runs as
#   go test -run '^$' -fuzz '^FuzzX$' -fuzztime T -parallel P ./pkg
# with every test process held to one core (GOMAXPROCS=1), so the campaign
# uses about FUZZ_JOBS * FUZZ_PARALLEL cores; the rest of the targets wait in
# a queue.
#
# Environment:
#   FUZZ_TIME      -fuzztime per target, a duration or Nx (default 5m)
#   FUZZ_PARALLEL  fuzzing workers per target (default 2)
#   FUZZ_JOBS      targets at once (default nproc / FUZZ_PARALLEL)
#   FUZZ_MINIMIZE  -fuzzminimizetime (default 1000x: minimising an input whose
#                  coverage depends on goroutine timing otherwise stalls a run)
#   FUZZ_SLACK     seconds a target may run past FUZZ_TIME for the build and
#                  the minimisation before it is killed (default 300)
#
# Logs go to bench/fuzz/<timestamp>/<pkg>_<target>.log. A failing target
# leaves its reproducer in <pkg>/testdata/fuzz/<target>/, which plain
# `go test` then replays; the summary prints the path.
set -euo pipefail

cd "$(dirname "$0")/.."

FUZZ_TIME="${FUZZ_TIME:-5m}"
FUZZ_PARALLEL="${FUZZ_PARALLEL:-2}"
FUZZ_MINIMIZE="${FUZZ_MINIMIZE:-1000x}"
FUZZ_SLACK="${FUZZ_SLACK:-300}"
cores="$(nproc 2>/dev/null || echo 2)"
FUZZ_JOBS="${FUZZ_JOBS:-$((cores / FUZZ_PARALLEL))}"
if [ "$FUZZ_JOBS" -lt 1 ]; then
	FUZZ_JOBS=1
fi
select_re="${1:-.}"

# deadline turns FUZZ_TIME into seconds for timeout(1). 0 means no deadline:
# that is what an iteration count (Nx) or a compound duration gets.
deadline() {
	local t="$1"
	if [[ "$t" =~ ^([0-9]+)([smh])$ ]]; then
		local n="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[2]}"
		case "$unit" in
		h) n=$((n * 3600)) ;;
		m) n=$((n * 60)) ;;
		esac
		echo $((n + FUZZ_SLACK))
	else
		echo 0
	fi
}
limit="$(deadline "$FUZZ_TIME")"

module="$(go list -m)"
discover() {
	local dir rel f
	while IFS= read -r dir; do
		rel="${dir#"$PWD"/}"
		if [ "$rel" = "$dir" ]; then
			rel="."
		fi
		for f in "$dir"/*_test.go; do
			[ -e "$f" ] || continue
			sed -nE "s|^func (Fuzz[A-Za-z0-9_]*)\(f \*testing\.F\).*|$rel \1|p" "$f"
		done
	done < <(go list -f '{{.Dir}}' ./...)
}
targets=()
while IFS= read -r line; do
	if [[ "${line/ /.}" =~ $select_re ]]; then
		targets+=("$line")
	fi
done < <(discover | sort -u)

if [ "${#targets[@]}" -eq 0 ]; then
	echo "no fuzz target matches '$select_re'" >&2
	exit 2
fi

stamp="$(date +%Y%m%d-%H%M%S)"
out="bench/fuzz/$stamp"
mkdir -p "$out"
echo "module $module: ${#targets[@]} targets, fuzztime $FUZZ_TIME, $FUZZ_PARALLEL workers each, $FUZZ_JOBS at once"
echo "logs: $out"

run_target() {
	local rel="$1" name="$2" log="$3"
	local rc=0
	timeout --kill-after=30s "$limit" \
		go test -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZ_TIME" -fuzzminimizetime "$FUZZ_MINIMIZE" \
		-parallel "$FUZZ_PARALLEL" -p "$FUZZ_PARALLEL" -exec 'env GOMAXPROCS=1' "./$rel" >"$log" 2>&1 || rc=$?
	echo "$rc" >"$log.rc"
}

stop() {
	echo "interrupted, stopping the running targets" >&2
	for p in $(jobs -p); do
		pkill -TERM -P "$p" 2>/dev/null || true
	done
	wait || true
	exit 130
}
trap stop INT TERM

logs=()
for t in "${targets[@]}"; do
	rel="${t% *}"
	name="${t#* }"
	log="$out/$(echo "$rel" | tr '/.' '__')_$name.log"
	logs+=("$rel|$name|$log")
	while [ "$(jobs -rp | wc -l)" -ge "$FUZZ_JOBS" ]; do
		wait -n || true
	done
	echo "start $rel $name"
	run_target "$rel" "$name" "$log" &
done
wait || true
trap - INT TERM

failed=0
printf '\n%-52s %-8s %14s %8s\n' "target" "result" "execs" "new"
for entry in "${logs[@]}"; do
	IFS='|' read -r rel name log <<<"$entry"
	rc="$(cat "$log.rc" 2>/dev/null || echo 1)"
	last="$(grep -E '^fuzz: elapsed' "$log" | tail -n 1 || true)"
	execs="$(sed -nE 's/.*execs: ([0-9]+).*/\1/p' <<<"$last")"
	new="$(sed -nE 's/.*new interesting: ([0-9]+).*/\1/p' <<<"$last")"
	result=ok
	if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
		result=TIMEOUT
		failed=1
	elif [ "$rc" != 0 ]; then
		result=FAIL
		failed=1
	fi
	printf '%-52s %-8s %14s %8s\n' "$rel.$name" "$result" "${execs:--}" "${new:--}"
done

if [ "$failed" -ne 0 ]; then
	echo
	for entry in "${logs[@]}"; do
		IFS='|' read -r rel name log <<<"$entry"
		if [ "$(cat "$log.rc" 2>/dev/null || echo 1)" = 0 ]; then
			continue
		fi
		repro="$(sed -nE 's/.*Failing input written to (testdata\/fuzz\/[^ ]+).*/\1/p' "$log" | tail -n 1)"
		if [ -z "$repro" ]; then
			# A reproducer already in testdata fails before fuzzing starts.
			seed="$(sed -nE "s/.*(seed corpus entry: |--- FAIL: )$name\/([0-9a-f]+).*/\2/p" "$log" | head -n 1)"
			if [ -n "$seed" ] && [ -e "$rel/testdata/fuzz/$name/$seed" ]; then
				repro="testdata/fuzz/$name/$seed"
			fi
		fi
		if [ -n "$repro" ]; then
			echo "$rel.$name: reproducer $rel/$repro (go test -run '$name/${repro##*/}' ./$rel), log $log"
		else
			echo "$rel.$name: no reproducer written, see $log"
		fi
	done
	exit 1
fi
