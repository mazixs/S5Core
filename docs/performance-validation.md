# Проверка производительности

Стенд выполняет настоящий HTTPS через отдельные процессы `s5client` и `s5core`. Origin и генератор находятся в процессе теста `cmd/httpsprobe`. TLS доверяет временному тестовому CA; каждое тело проверяется по размеру и SHA-256. Сервер использует настоящий SDK, Prometheus scrape идет каждые 250 мс. При заданном аккаунте traffic flush также идет каждые 250 мс. Пользовательские переменные с credentials в дочерние процессы не наследуются.

## Подготовка

Нужны Linux, Go из `go.mod`, Python 3. Для netem дополнительно нужны `unshare`, `ip`, `tc` и поддержка user/network namespaces. Сохраните baseline **рабочего дерева**, включая незакоммиченные исправления. SHA одного коммита недостаточен. Нельзя брать исходные числа из старого отчета за baseline изменившегося кода.

```bash
go build -pgo=off -o /tmp/s5client-after ./cmd/s5client
go build -pgo=off -o /tmp/s5core-after ./cmd/s5core
go test -c -o /tmp/s5-perf-probe ./cmd/httpsprobe

S5_PERF_SMALL=1700 S5_PERF_LARGE=15 S5_PERF_PROTOCOLS=h1 \
python3 scripts/performance-ab.py \
  --probe /tmp/s5-perf-probe \
  --before-client /tmp/s5client-before --before-server /tmp/s5core-before \
  --after-client /tmp/s5client-after --after-server /tmp/s5core-after \
  --rounds 6 --out /tmp/s5-perf-abba

python3 scripts/performance-summary.py /tmp/s5-perf-abba \
  --json /tmp/s5-perf-summary.json > /tmp/s5-perf-summary.md
```

Все каталоги вывода должны быть новыми. `performance-ab.py` выполняет A/B/B/A последовательно, записывает хеши бинарей, CPU, лимиты cgroup и параметры стенда. Не запускайте одновременно сборки, race, другие benchmarks. При `1700` запросах и шести прогонах получается 10200 наблюдений на вариант и сценарий. Доверительный интервал в сводке относится к медиане **p99 отдельных прогонов**, bootstrap пересэмплирует прогоны. Колонка p99 содержит квантиль объединенных запросов. Для больших тел с 90 наблюдениями p99 - диагностическое значение, не надежная оценка хвоста.

`resources.jsonl` содержит CPU ticks, RSS и high-water RSS каждого прокси до и после сценария. Новые записи также содержат `GeneratorBefore/After` для общего процесса origin/генератора. Скрипт записывает `SC_CLK_TCK` в metadata и использует его при пересчете; для старых файлов без этого поля применяется 100. В сводке CPU cores означает CPU-seconds / wall-seconds. Для upload полезный объем включает загруженные байты. Для mixed фоновый объем пока не подсчитывается, поэтому CPU/GiB отсутствует в сводке. Время `total_ms` включает SHA-256 на стороне генератора; CPU профили прокси его не включают. RSS включает память предыдущих сценариев и состояние GC; это не точный размер одного соединения. Незавершенная серия с `completed=false` не принимается скриптом сводки.

Генератору и origin нужен запас CPU. `S5_PERF_PROCS` ограничивает только прокси, а `GOMAXPROCS` окружения теста ограничивает сам генератор. На слабом общем хосте ускоренный туннель может упереться в TLS/SHA-256 генератора; его очередь станет частью измеренной задержки. Учитывайте это при сравнении mixed, особенно если генератору оставлен один Go P. Для приемки рабочего маршрута предпочтительны отдельные хосты origin/генератора и прокси.

## Сценарии

| Переменная | Значение по умолчанию | Назначение |
| --- | --- | --- |
| `S5_PERF_MODES` | `direct,plain,obfs,wss` | Пути передачи |
| `S5_PERF_PROTOCOLS` | `h1,h2` | Проверяется реально согласованный протокол |
| `S5_PERF_REUSE` | `new,reuse` | Новый TLS или повторное использование |
| `S5_PERF_CASES` | `small,large,upload` | Также `mixed`, `stream` и `upload-stream` |
| `S5_PERF_SMALL` / `S5_PERF_LARGE` | `100` / `15` | Число измеренных запросов; три прогрева отдельно |
| `S5_PERF_CONCURRENCY` | `1` | Одновременные запросы; HTTP/2 может мультиплексировать их в одном туннеле |
| `S5_PERF_PROCS` | `16` | GOMAXPROCS каждого прокси; для ограниченного стенда задать `1` |
| `S5_PERF_AUTH` | пусто | Лабораторный NoAuth; `member`, `fallback` или `password` создают временный аккаунт |
| `S5_PERF_TLS_CACHE` | включен у нового клиента | `0` выключает кеш для отдельного A/B |
| `S5_PERF_FINGERPRINT` | пусто | Профиль uTLS |
| `S5_PERF_FQDN` | `0` | `1` использует localhost вместо IP origin, сохраняя проверку сертификата |
| `S5_PERF_ROUTES` | не задана | Количество доменных правил; задавать с `S5_PERF_FQDN=1` |
| `S5_PERF_PROFILE` | `0` | `1` сохраняет профили диагностических бинарей |
| `S5_PERF_TRACE` | `0` | Вместе с PROFILE включает runtime trace и GC trace только для диагностики |
| `S5_PERF_WS_MAX_FRAME` | `4096` | Переопределяет shaping обоих концов для проверки нестандартных размеров |

`stream` и `upload-stream` передают 350 блоков по 32 КиБ с интервалом 100 мс, более 35 секунд, в соответствующем направлении. `mixed` выполняет малые запросы одновременно с повторными загрузками 8 МиБ. Для проверки старый клиент/новый сервер и наоборот передайте нужные пары путей. Для member-auth оставляйте только `obfs,wss`: plain-ветка генератора намеренно без credentials.

NoAuth разрешен только в изолированном лабораторном стенде. Для рабочего клиента режим `PROXY_AUTH_MODE=member-only` требует `OBFS_MEMBER_ID`, `OBFS_MEMBER_KEY` и пустые `PROXY_USER/PROXY_PASS` (с 2.2 формат провода один, и `OBFS_FORMAT` режим больше не проверяет). `RequireAuth` сервера сохраняется. `password-fallback` разрешает выбор SOCKS user/pass после успешной проверки obfs, но не повторяет попытку с другим ключом при отказе obfs. Не используйте этот режим как способ скрыть отзыв аккаунта.

## Изолированная сеть

```bash
S5_PERF_MODES=obfs,wss S5_PERF_SMALL=20 S5_PERF_LARGE=3 \
S5_PERF_PROTOCOLS=h1 S5_PERF_REUSE=new \
scripts/performance-netem.sh 50 0.1 100 \
  python3 scripts/performance-ab.py \
  --probe /tmp/s5-perf-probe \
  --before-client /tmp/s5client-before --before-server /tmp/s5core-before \
  --after-client /tmp/s5client-after --after-server /tmp/s5core-after \
  --rounds 2 --out /tmp/s5-netem-smoke
```

Аргументы: RTT в мс, loss в процентах, полоса в Мбит/с. Обе стороны TCP получают половину RTT; netem применяется только к портам туннеля 41443/41444. Origin, клиентский SOCKS и direct/plain проходят без этого ограничения. Скрипт отказывается работать в исходном network namespace. Рабочие интерфейсы не изменяются. MTU изолированного lo равен 1500, его можно изменить через `S5_NETEM_MTU`; obfs MTU остается 1400. В конце сохраняются счетчики qdisc и TCP: проверяйте drops/backlog/retransmits, не приписывайте искусственную потерю приложению. Это модель на loopback, а не измерение роутера, провайдера или аппаратных offload.

## Профили и PGO

```bash
go build -tags=profiling -pgo=off -o /tmp/s5client-profile ./cmd/s5client
go build -tags=profiling -pgo=off -o /tmp/s5core-profile ./cmd/s5core
```

Только эти сборки читают `S5_PROFILE_DIR`, создавая `cpu`, `allocs`, `heap`, `mutex`, `block` и `goroutine` в отдельных файлах с правами 0600. Каталог должен быть новым для каждого процесса. Профили завершаются при штатном SIGTERM. HTTP pprof не публикуется; обычные релизные сборки не включают профилировщик. Ошибка или SIGKILL могут оставить неполный профиль. Профили сами меняют стоимость работы, поэтому A/B для выпуска выполняется без них.

Для PGO соберите отдельный профиль каждого бинаря после стабилизации кода, с распределением нагрузок рабочего маршрута. Сравните `go build -pgo=off` и `go build -pgo=/path/to/own/cpu.pprof` на независимой приемочной серии, сохраните время сборки и размер бинаря. Не переносите совмещенный профиль origin/генератора и не добавляйте лабораторный профиль как production `default.pgo`. Порог принятия из плана: минимум 3% и сохранение latency/memory-приемки.

## Граница приемки

Полный план включает настоящий arm64, рабочий WAN/VPS, quotas/revoke, UDP при потере, пики нагрузки и canary с откатом. Кросс-сборка ARM не заменяет эти испытания. Нельзя объявлять локальный результат выпуском. Результаты текущей реализации и непроверенные пункты перечислены в [отчете](reports/performance-implementation-2026-09-22.md).
