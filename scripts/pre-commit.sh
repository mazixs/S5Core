#!/usr/bin/env bash
#
# pre-commit.sh - единственный источник истины по проверкам качества.
#
# Тот же скрипт запускает CI (.github/workflows/ci.yml), поэтому локальный
# прогон и прогон в GitHub дают одинаковый вердикт. Расхождение между ними -
# это баг скрипта или workflow, а не "особенность окружения".
#
# Воспроизводимый прогон в том же окружении, что и CI:
#   docker run --rm -v "$PWD":/src -w /src golang:1.26.6 ./scripts/pre-commit.sh
#
# Переменные окружения:
#   SKIP_LINT=1   пропустить golangci-lint (нужна сеть для установки)
#   SKIP_VULN=1   пропустить govulncheck   (нужна сеть: база уязвимостей)
#   SKIP_SLOW=1   пропустить race-тесты и сборку бинарей (быстрая проверка стиля)

set -uo pipefail

GO_VERSION_EXPECTED="1.26.6"
GOLANGCI_LINT_VERSION="v2.13.2"
# Закреплено, как и golangci-lint выше: @latest означает, что один и тот же
# коммит проверяется разными сканерами у разработчика и в CI, и "у меня было
# зелено" перестает быть утверждением о коде. Версия поднимается правкой этой
# строки, а не тем, что кто-то однажды запустил скрипт позже других.
GOVULNCHECK_VERSION="v1.8.0"

failed=0
step() { current_step="$1"; printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32mok\033[0m %s\n' "$1"; }
bad() {
	printf '   \033[31mFAIL\033[0m %s\n' "$1"
	failed=1
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		local message="check=$current_step: $1"
		message="${message//'%'/'%25'}"
		message="${message//$'\r'/'%0D'}"
		message="${message//$'\n'/'%0A'}"
		printf '::error title=Quality check failed::%s\n' "$message"
	fi
}

GOBIN_DIR="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN_DIR"

# В контейнере репозиторий принадлежит другому пользователю, и git отказывается
# его читать. Без этого go build падает на VCS-штампе, а не на коде.
if [ -d .git ] && command -v git >/dev/null 2>&1; then
	git config --global --add safe.directory "$PWD" >/dev/null 2>&1 || true
fi

# Инструмент ставится сюда же, а не советуется в сообщении об ошибке:
# совет, который надо выполнить руками, - это причина, по которой шаг
# годами не выполняется ни у кого.
ensure_tool() {
	local bin="$1" pkg="$2"
	if command -v "$bin" >/dev/null 2>&1; then return 0; fi
	printf '   ставлю %s (%s)\n' "$bin" "$pkg"
	local install_output
	if ! install_output="$(go install "$pkg" 2>&1)"; then
		printf '%s\n' "$install_output"
		return 1
	fi
	command -v "$bin" >/dev/null 2>&1
}

step "Версия toolchain"
go_version="$(go version | awk '{print $3}' | sed 's/^go//')"
if [ "$go_version" = "$GO_VERSION_EXPECTED" ]; then
	ok "go $go_version"
else
	printf '   \033[33mwarn\033[0m локально go %s, ожидается %s (toolchain берется из go.mod)\n' \
		"$go_version" "$GO_VERSION_EXPECTED"
fi

step "Целостность зависимостей (go mod verify)"
if go mod verify >/dev/null; then ok "модули не изменены"; else bad "go mod verify"; fi

step "Форматирование (gofmt -s)"
unformatted="$(gofmt -s -l . | grep -v '^vendor/' || true)"
if [ -z "$unformatted" ]; then
	ok "все файлы отформатированы"
else
	bad "не отформатированы:"
	printf '        %s\n' $unformatted
	printf '        исправить: gofmt -s -w .\n'
fi

step "Символы в исходниках"
# Длинное тире приезжает в код копипастой и генераторами, и однажды доехало до
# строки, которую печатает клиент при каждом запуске (ревью R13): терминал,
# журнал и почта рендерят его по-разному, а дефис везде одинаков. Ищется по
# байтам UTF-8, а не через grep -P, которого нет в busybox.
emdash="$(grep -rl "$(printf '\342\200\224')" --include='*.go' . || true)"
if [ -z "$emdash" ]; then
	ok "длинного тире в .go нет"
else
	bad "длинное тире (U+2014), заменить на дефис:"
	printf '        %s\n' $emdash
fi

step "Актуальность go.mod (go mod tidy -diff)"
# -diff ничего не переписывает и отвечает кодом возврата. Раньше здесь
# делалась копия go.mod/go.sum, запускался tidy с подавленным выводом и
# сравнивались файлы - и отказ самого tidy (например, без сети) выглядел как
# "изменений нет", то есть шаг зеленел ровно тогда, когда не выполнялся.
if tidy_diff="$(go mod tidy -diff 2>&1)"; then
	ok "go.mod и go.sum актуальны"
else
	bad "go mod tidy меняет go.mod/go.sum либо сам не отработал"
	printf '%s\n' "$tidy_diff" | head -20
fi

step "go vet"
if go vet ./...; then ok "vet чист"; else bad "go vet"; fi

step "Статический анализ (golangci-lint $GOLANGCI_LINT_VERSION)"
if [ "${SKIP_LINT:-0}" = "1" ]; then
	printf '   пропущено (SKIP_LINT=1)\n'
elif ensure_tool golangci-lint "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GOLANGCI_LINT_VERSION"; then
	if golangci-lint run ./...; then ok "0 замечаний"; else bad "golangci-lint"; fi
else
	bad "golangci-lint недоступен и не установился (причина выше) - SKIP_LINT=1 чтобы пропустить"
fi

step "Уязвимости зависимостей (govulncheck)"
if [ "${SKIP_VULN:-0}" = "1" ]; then
	printf '   пропущено (SKIP_VULN=1)\n'
elif ensure_tool govulncheck "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"; then
	if govulncheck ./...; then ok "вызываемых уязвимостей нет"; else bad "govulncheck"; fi
else
	bad "govulncheck недоступен и не установился (причина выше) - SKIP_VULN=1 чтобы пропустить"
fi

if [ "${SKIP_SLOW:-0}" = "1" ]; then
	printf '\n   тесты и сборка пропущены (SKIP_SLOW=1)\n'
else
	step "Тесты с детектором гонок"
	report_dir="${CI_REPORT_DIR:-.ci-reports}"
	if mkdir -p "$report_dir" && go build -o "$report_dir/testreport" ./scripts/testreport; then
		# pipefail preserves test, disk-write and reporter failures separately
		# from the success of the last command. JSON remains available as an artifact.
		if go test -json -race -coverprofile=coverage.txt -covermode=atomic ./... 2> "$report_dir/tests.stderr.log" |
			tee "$report_dir/tests.jsonl" | "$report_dir/testreport"; then
			ok "тесты зеленые"
		else
			bad "go test -race: см. CI_FAILURE и .ci-reports/tests.jsonl"
		fi
		cat "$report_dir/tests.stderr.log"
		rm -f "$report_dir/testreport"
	else
		bad "не удалось подготовить отчет go test"
	fi

	# Один проход по каждому бенчмарку: они не измеряют здесь ничего, но
	# перестают тихо гнить. Гейты производительности живут в обычных тестах
	# (pkg/obfs/alloc_test.go) - они детерминированы и не зависят от того,
	# насколько занят раннер.
	step "Бенчмарки запускаются"
	if benchmark_output="$(go test -run XXX -bench=. -benchtime=1x ./pkg/obfs/ ./pkg/transport/ws/ 2>&1)"; then
		ok "бенчмарки живы"
	else
		printf '%s\n' "$benchmark_output"
		bad "бенчмарки"
	fi

	# Цели берутся из release.yml, а не перечисляются здесь: иначе поломка
	# сборки под одну из них (32-битный MIPS) всплыла бы в job релиза уже
	# после публикации Docker-образов.
	step "Сборка бинарей под цели релиза"
	release_builds="$(sed -n 's/^ *\(GOOS=[^ ]*\( GO[A-Z]*=[^ ]*\)*\) go build .* \(\.\/cmd\/[a-z0-9]*\)$/\1 \3/p' .github/workflows/release.yml)"
	if [ -z "$release_builds" ]; then
		bad "в .github/workflows/release.yml не найдено ни одной строки go build"
	else
		build_failed=0
		while read -r build; do
			# shellcheck disable=SC2086 # переменные цели разбиваются на слова намеренно
			if ! env ${build% *} go build -o /dev/null "${build##* }"; then
				bad "сборка: $build"
				build_failed=1
			fi
		done <<< "$release_builds"
		[ "$build_failed" -eq 0 ] && ok "$(wc -l <<< "$release_builds") целей из release.yml собираются"
	fi
fi

printf '\n'
if [ "$failed" -eq 0 ]; then
	printf '\033[32mВсе проверки пройдены.\033[0m\n'
	exit 0
fi
printf '\033[31mЕсть непройденные проверки (см. FAIL выше).\033[0m\n'
exit 1
