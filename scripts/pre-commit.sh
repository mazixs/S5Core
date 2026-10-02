#!/usr/bin/env bash
#
# pre-commit.sh - единственный источник истины по проверкам качества.
#
# Тот же скрипт запускает CI (.github/workflows/ci.yml), поэтому локальный
# прогон и прогон в GitHub дают одинаковый вердикт. Расхождение между ними -
# это баг скрипта или workflow, а не "особенность окружения".
#
# Воспроизводимый прогон в том же окружении, что и CI:
#   docker run --rm -v "$PWD":/src -w /src golang:1.26.8 ./scripts/pre-commit.sh
#
# Переменные окружения:
#   SKIP_LINT=1   пропустить golangci-lint (нужна сеть для установки)
#   SKIP_VULN=1   пропустить govulncheck   (нужна сеть: база уязвимостей)
#   SKIP_SLOW=1   пропустить race-тесты, сборку бинарей, smoke и метрики (быстрая проверка стиля)
#
# Что остается после прогона (CI_REPORT_DIR, по умолчанию .ci-reports):
#   tests.jsonl, summary.md, metrics.json; coverage.txt лежит в корне.

set -uo pipefail

GO_VERSION_EXPECTED="1.26.8"
GOLANGCI_LINT_VERSION="v2.14.0"
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
	local bin="$1" pkg="$2" dir
	# Каталог под версию: найденный в PATH бинарь той версии не заменяет,
	# а snap или пакетный менеджер обновляют его без нас.
	dir="$(go env GOPATH)/s5core-tools/$bin-${pkg##*@}"
	if [ ! -x "$dir/$bin" ]; then
		printf '   ставлю %s (%s)\n' "$bin" "$pkg"
		local install_output
		if ! install_output="$(GOBIN="$dir" go install "$pkg" 2>&1)"; then
			printf '%s\n' "$install_output"
			return 1
		fi
	fi
	PATH="$dir:$PATH"
}

step "Версия toolchain"
go_version="$(go version | awk '{print $3}' | sed 's/^go//')"
if [ "$go_version" = "$GO_VERSION_EXPECTED" ]; then
	ok "go $go_version"
else
	printf '   \033[33mwarn\033[0m локально go %s, ожидается %s (toolchain берется из go.mod)\n' \
		"$go_version" "$GO_VERSION_EXPECTED"
fi

step "Согласованность версий Go"
# Версия живет в пяти местах, и расхождение между ними - это "локально зелено,
# в образе релиза другой компилятор". Поднимается одной правкой всех пяти.
version_of() { sed -n "$1" "$2" | head -1; }
for entry in \
	"go.mod (toolchain)|$(awk '$1=="toolchain"{sub(/^go/,"",$2);print $2}' go.mod)" \
	"Dockerfile (GOLANG_VERSION)|$(version_of 's/^ARG GOLANG_VERSION="\{0,1\}\([0-9.]*\).*/\1/p' Dockerfile)" \
	"ci.yml (container)|$(version_of 's/^ *container: golang:\([0-9.]*\).*/\1/p' .github/workflows/ci.yml)" \
	"release.yml (container)|$(version_of 's/^ *container: golang:\([0-9.]*\).*/\1/p' .github/workflows/release.yml)" \
	"release.yml (setup-go)|$(version_of "s/^ *go-version: '\\([0-9.]*\\)'.*/\\1/p" .github/workflows/release.yml)"; do
	if [ "${entry#*|}" = "$GO_VERSION_EXPECTED" ]; then
		ok "${entry%%|*}: $GO_VERSION_EXPECTED"
	else
		bad "${entry%%|*}: '${entry#*|}', в этом скрипте $GO_VERSION_EXPECTED"
	fi
done

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
# байтам UTF-8, а не через grep -P, которого нет в busybox. Файлы, которые git
# игнорирует, не проверяются: в CI их нет, и вердикты разошлись бы.
# safe.directory: в контейнере репозиторий принадлежит другому uid, git без
# него отказывает, и пустой список файлов выглядел бы как чистый.
dash="$(printf '\342\200\224')"
if command -v git >/dev/null 2>&1 && git -c safe.directory='*' rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	emdash="$(git -c safe.directory='*' ls-files -co --exclude-standard -z -- '*.go' | xargs -0 -r grep -l "$dash" || true)"
else
	emdash="$(grep -rl "$dash" --include='*.go' . || true)"
fi
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
	mkdir -p "$report_dir" && rm -f coverage.txt "$report_dir/tests.jsonl" "$report_dir/summary.md" "$report_dir/metrics.json"
	if go build -o "$report_dir/testreport" ./scripts/testreport; then
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
	# после публикации Docker-образов. Бинари остаются в $report_dir/bin под теми
	# же именами и флагами, что у файлов релиза: по ним считаются размеры и
	# гоняется smoke. После проверок они удаляются (в артефакт CI не идут).
	step "Сборка бинарей под цели релиза"
	bin_dir="$report_dir/bin"
	build_version="${CI_BUILD_VERSION:-ci}"
	rm -rf "$bin_dir"
	mkdir -p "$bin_dir"
	release_builds="$(sed -n 's/^ *\(GOOS=[^ ]*\( GO[A-Z]*=[^ ]*\)*\) go build .* \(\.\/cmd\/[a-z0-9]*\)$/\1 \3/p' .github/workflows/release.yml)"
	if [ -z "$release_builds" ]; then
		bad "в .github/workflows/release.yml не найдено ни одной строки go build"
	else
		build_failed=0
		while read -r build; do
			target_env="${build% *}"
			cmd_pkg="${build##* }"
			goos="" goarch="" gomips=""
			for kv in $target_env; do
				case "$kv" in
					GOOS=*) goos="${kv#GOOS=}" ;;
					GOARCH=*) goarch="${kv#GOARCH=}" ;;
					GOMIPS=*) gomips="${kv#GOMIPS=}" ;;
				esac
			done
			bin_name="${cmd_pkg##*/}-$goos-$goarch"
			[ -n "$gomips" ] && bin_name="$bin_name-$gomips"
			[ "$goos" = "windows" ] && bin_name="$bin_name.exe"
			# CGO_ENABLED=0 и флаги, как в шаге сборки release.yml: нативная цель
			# иначе собиралась бы здесь с cgo, а в релиз уходит без него.
			# shellcheck disable=SC2086 # переменные цели разбиваются на слова намеренно
			if ! env CGO_ENABLED=0 $target_env go build -trimpath \
				-ldflags "-s -w -X github.com/mazixs/S5Core/internal/buildinfo.version=$build_version" \
				-o "$bin_dir/$bin_name" "$cmd_pkg"; then
				bad "сборка: $build"
				build_failed=1
			fi
		done <<< "$release_builds"
		[ "$build_failed" -eq 0 ] && ok "$(wc -l <<< "$release_builds") целей из release.yml собираются"
	fi

	# Настоящие бинари, а не тесты внутри процесса: ловит то, что видно только
	# в собранном файле (переменная окружения, штамп версии, WARN на чистом
	# прогоне, процесс, не гаснущий по SIGTERM).
	step "Smoke настоящих s5core и s5client"
	host_suffix="$(go env GOOS)-$(go env GOARCH)"
	if [ "$(go env GOOS)" != "linux" ] || [ ! -x "$bin_dir/s5core-$host_suffix" ]; then
		printf '   пропущено: smoke идет на linux, а для %s бинаря релиза нет\n' "$host_suffix"
	elif go run ./scripts/smoke -core "$bin_dir/s5core-$host_suffix" -client "$bin_dir/s5client-$host_suffix" -version "$build_version"; then
		ok "TCP, UDP native, метрики и логи"
	else
		bad "smoke: см. вывод выше"
	fi

	step "Метрики и бюджеты"
	if [ -s coverage.txt ] && [ -s "$report_dir/tests.jsonl" ]; then
		if go run ./scripts/metrics -tests "$report_dir/tests.jsonl" -coverage coverage.txt \
			-bins "$bin_dir" -budgets scripts/budgets.txt -out "$report_dir"; then
			ok "бюджеты scripts/budgets.txt соблюдены (сводка: $report_dir/summary.md)"
		else
			bad "бюджеты scripts/budgets.txt нарушены (см. выше); сознательное изменение - правка файла с причиной в коммите"
		fi
		if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$report_dir/summary.md" ]; then
			cat "$report_dir/summary.md" >> "$GITHUB_STEP_SUMMARY"
		fi
	else
		bad "нет coverage.txt или tests.jsonl: метрики считать не из чего"
	fi
	rm -rf "$bin_dir"
fi

printf '\n'
if [ "$failed" -eq 0 ]; then
	printf '\033[32mВсе проверки пройдены.\033[0m\n'
	exit 0
fi
printf '\033[31mЕсть непройденные проверки (см. FAIL выше).\033[0m\n'
exit 1
