# Проверка производительности

Стенд выполняет настоящий HTTPS через отдельные процессы `s5client` и `s5core`. Origin и генератор находятся в процессе теста `cmd/httpsprobe`. TLS доверяет временному тестовому CA; каждое тело проверяется по размеру и SHA-256. Сервер использует настоящий SDK, Prometheus scrape по умолчанию идет каждые 250 мс; хотя бы один неудачный scrape проваливает режим. При заданном аккаунте traffic flush также идет каждые 250 мс. Пользовательские переменные с credentials в дочерние процессы не наследуются.

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

Все каталоги вывода должны быть новыми. `performance-ab.py` выполняет A/B/B/A последовательно, записывает хеши бинарей, `/proc/cpuinfo`, [контекст ресурсов](#контекст-ресурсов-прогона) каждого прогона и параметры стенда. `--before-env` и `--after-env` задают переменную `S5_PERF_*` только для своего варианта, например `--after-env S5_PERF_DIAGNOSTICS=1`; они записываются в `variant_environment`. Не запускайте одновременно сборки, race, другие benchmarks. При `1700` запросах и шести прогонах получается 10200 наблюдений на вариант и сценарий. Доверительный интервал в сводке относится к медиане **p99 отдельных прогонов**, bootstrap пересэмплирует прогоны. Колонка p99 содержит квантиль объединенных запросов. Для больших тел с 90 наблюдениями p99 - диагностическое значение, не надежная оценка хвоста.

`resources.jsonl` содержит CPU ticks, RSS, high-water RSS и число открытых дескрипторов (`open_fds`) каждого прокси до и после сценария. Новые записи также содержат `GeneratorBefore/After` для общего процесса origin/генератора. Скрипт записывает `SC_CLK_TCK` в metadata и использует его при пересчете; для старых файлов без этого поля применяется 100. В сводке CPU cores означает CPU-seconds / wall-seconds. Для upload полезный объем включает загруженные байты. Фоновый объем mixed записывается в `BackgroundBytes` и `BackgroundRequests`, но сводка его не учитывает, поэтому CPU/GiB для mixed в ней нет. Записи `idle` и `idle-tunnel` в сводку не попадают: у них нет запросов. Время `total_ms` включает SHA-256 на стороне генератора; CPU профили прокси его не включают. RSS включает память предыдущих сценариев и состояние GC; это не точный размер одного соединения. Незавершенная серия с `completed=false` не принимается скриптом сводки.

Генератору и origin нужен запас CPU. `S5_PERF_PROCS` ограничивает только прокси, а `GOMAXPROCS` окружения теста ограничивает сам генератор. На слабом общем хосте ускоренный туннель может упереться в TLS/SHA-256 генератора; его очередь станет частью измеренной задержки. Учитывайте это при сравнении mixed, особенно если генератору оставлен один Go P. Для приемки рабочего маршрута предпочтительны отдельные хосты origin/генератора и прокси.

## Сценарии

| Переменная | Значение по умолчанию | Назначение |
| --- | --- | --- |
| `S5_PERF_MODES` | `direct,plain,obfs,wss` | Пути передачи |
| `S5_PERF_PROTOCOLS` | `h1,h2` | Проверяется реально согласованный протокол |
| `S5_PERF_REUSE` | `new,reuse` | Новый TLS или повторное использование |
| `S5_PERF_CASES` | `small,large,upload` | Также `mixed`, `stream`, `upload-stream`, `slow-read` и `idle-tunnel` |
| `S5_PERF_SMALL` / `S5_PERF_LARGE` | `100` / `15` | Число измеренных запросов; три прогрева отдельно |
| `S5_PERF_CONCURRENCY` | `1` | Одновременные запросы; HTTP/2 может мультиплексировать их в одном туннеле |
| `S5_PERF_PROCS` | `16` | GOMAXPROCS каждого прокси; для ограниченного стенда задать `1`, `auto` оставляет значение Go по умолчанию |
| `S5_PERF_CYCLES` | `1` | Сколько раз повторить сценарии каждой пары протокол/reuse на тех же процессах |
| `S5_PERF_MIN_DURATION` | не задана | Минимальная длительность нагрузки сценария: запросы идут, пока не набрано и число, и время |
| `S5_PERF_FIRST_DURATION` | не задана | То же для первого цикла |
| `S5_PERF_REQUEST_INTERVAL` | не задана | Запросы предлагаются по расписанию с этим шагом, а не по готовности воркера |
| `S5_PERF_BULK_INTERVAL` | не задана | Пауза после каждой фоновой загрузки 8 МиБ в `mixed` |
| `S5_PERF_SCRAPE_INTERVAL` | `250ms` | Период Prometheus scrape сервера |
| `S5_PERF_IDLE_DURATION` | не задана | Простой процессов перед сценариями режима, отдельная запись `Scenario="idle"` |
| `S5_PERF_RECOVERY_DURATION` | не задана | Пауза после каждого сценария, в конце записываются ресурсы прокси и последний scrape |
| `S5_PERF_SLOW_READ_DELAY` | `10ms` | Пауза генератора после каждого чтения в `slow-read` |
| `S5_PERF_IDLE_TUNNELS` | `8` | Число туннелей `idle-tunnel`, не больше 128 |
| `S5_PERF_TUNNEL_IDLE_DURATION` | `2m` | Сколько `idle-tunnel` держит туннели без данных |
| `S5_PERF_DIAGNOSTICS` | `0` | `1` включает [latency-диагностику](#стоимость-latency-диагностики) обоих прокси, `trace` — еще и flight recorder трассы |
| `S5_PERF_RECOVERY_MARKERS` | `0` | `1` завершает каждый период восстановления ручным инцидентом диагностики |
| `S5_PERF_FLOW_CONTEXT` | `0` | `1` добавляет к запросам в `requests.jsonl` адреса их TCP-соединения |
| `S5_PERF_AUTH` | пусто | Лабораторный NoAuth; `member`, `fallback` или `password` создают временный аккаунт |
| `S5_PERF_TLS_CACHE` | включен у нового клиента | `0` выключает кеш для отдельного A/B |
| `S5_PERF_FINGERPRINT` | пусто | Профиль uTLS |
| `S5_PERF_FQDN` | `0` | `1` использует localhost вместо IP origin, сохраняя проверку сертификата |
| `S5_PERF_ROUTES` | не задана | Количество доменных правил; задавать с `S5_PERF_FQDN=1` |
| `S5_PERF_PROFILE` | `0` | `1` сохраняет профили диагностических бинарей |
| `S5_PERF_TRACE` | `0` | Вместе с PROFILE включает runtime trace и GC trace только для диагностики |
| `S5_PERF_WS_MAX_FRAME` | `4096` | Переопределяет shaping обоих концов для проверки нестандартных размеров |

`stream` и `upload-stream` передают 350 блоков по 32 КиБ с интервалом 100 мс, более 35 секунд, в соответствующем направлении. `mixed` выполняет малые запросы одновременно с повторными загрузками 8 МиБ. `slow-read` загружает те же 8 МиБ, что `large`, но генератор читает тело порциями до 32 КиБ с паузой `S5_PERF_SLOW_READ_DELAY` после каждой. `idle-tunnel` — не HTTP: он открывает через прокси сырые TCP-туннели к локальному echo, проверяет каждый байтом эха, держит их без данных и снова проверяет эхо на тех же соединениях. Его запись в `resources.jsonl` имеет `Protocol="raw_tcp"`, `Reuse="held"`, а `Count` равен числу туннелей. Для проверки старый клиент/новый сервер и наоборот передайте нужные пары путей. Для member-auth оставляйте только `obfs,wss`: plain-ветка генератора намеренно без credentials.

Длительности задаются в формате Go (`500ms`, `2m`) и должны быть положительными. У каждой записи `resources.jsonl` есть границы фазы (`StartedAtUTC`, `EndedAtUTC`) и scrape за фазу (`Scrapes`, `ScrapeErrors`, `ScrapeNanoseconds`). С `S5_PERF_RECOVERY_DURATION` к записи добавляются `ServerRecovered`, `ClientRecovered`, `RecoveredAtUTC` и `RecoverySeconds`, а последний успешный scrape сервера к концу восстановления сохраняется в `metrics-<протокол>-<reuse>-<сценарий>-cycle-<N>-recovered.prom`; время этого scrape — в `RecoveredMetricsAtUTC`.

С `S5_PERF_REQUEST_INTERVAL` у запроса в `requests.jsonl` есть `offer_delay_ns` — от планового старта до начала запроса воркером, и `scheduled_total_ms` — от планового старта до конца запроса. Без расписания `offer_delay_ns` равен 0, а `scheduled_total_ms` — `total_ms`. В `resources.jsonl` `LateOffers` считает запросы, начатые позже планового старта больше чем на шаг расписания, а `MaxOfferDelayNanoseconds` — наибольшую задержку старта. Поздние запросы значат, что генератор не выдержал расписание, и нагрузка вариантов уже не равна.

NoAuth разрешен только в изолированном лабораторном стенде. Для рабочего клиента режим `PROXY_AUTH_MODE=member-only` требует `OBFS_MEMBER_ID`, `OBFS_MEMBER_KEY` и пустые `PROXY_USER/PROXY_PASS` (с 2.2 формат провода один, и `OBFS_FORMAT` режим больше не проверяет). `RequireAuth` сервера сохраняется. `password-fallback` разрешает выбор SOCKS user/pass после успешной проверки obfs, но не повторяет попытку с другим ключом при отказе obfs. Не используйте этот режим как способ скрыть отзыв аккаунта.

## Стоимость latency-диагностики

`S5_PERF_DIAGNOSTICS=1` включает [latency-диагностику](../guides/operations.md#latency-diagnostics) каждого прокси режима. У процесса свой каталог, `<режим>/server/diagnostics` или `<режим>/client/diagnostics`, а общий `S5_DIAGNOSTICS_RUN_ID` связывает инциденты сервера и клиента одного режима. `trace` дополнительно задает `S5_DIAGNOSTICS_TRACE=1`. Если к концу режима каталог прокси не появился, рекордер не запустился, и режим проваливается.

Стоимость диагностики измеряет A/B одних и тех же бинарей, у вариантов которых различается только эта переменная:

```bash
S5_PERF_MODES=obfs,wss S5_PERF_SMALL=1700 S5_PERF_LARGE=15 \
S5_PERF_CASES=small,large,upload,mixed \
python3 scripts/performance-ab.py \
  --probe /tmp/s5-perf-probe \
  --before-client /tmp/s5client-after --before-server /tmp/s5core-after \
  --after-client /tmp/s5client-after --after-server /tmp/s5core-after \
  --after-env S5_PERF_DIAGNOSTICS=1 \
  --rounds 6 --out /tmp/s5-diag-abba

python3 scripts/performance-summary.py /tmp/s5-diag-abba \
  --json /tmp/s5-diag-summary.json > /tmp/s5-diag-summary.md
```

Сводка читает только `requests.jsonl` и `resources.jsonl`, файлы инцидентов она не открывает. Автоматический инцидент, если он случился в прогоне, входит в измеренную стоимость: его пишет на диск тот же процесс. CPU простоя с диагностикой и без нее (`S5_PERF_IDLE_DURATION`, `idle-tunnel`) сводка не считает: для записей `idle` и `idle-tunnel` это `ServerAfter.cpu_ticks − ServerBefore.cpu_ticks`, деленное на `SC_CLK_TCK` и `Seconds`, и то же для клиента.

`S5_PERF_RECOVERY_MARKERS=1` требует диагностики и `S5_PERF_RECOVERY_DURATION` не короче 90 с. За 90 с до конца каждого периода восстановления харнесс пишет один `trigger.json` в каталоги диагностики всех прокси режима и ждет, пока каждый рекордер сохранит инцидент: манифест появляется через 90 с после маркера. ID инцидента записывается в `RecoveryIncident` сценария. Инцидент содержит runtime-метрики прокси каждые 500 мс за две минуты до маркера и 90 с после него.

С `S5_PERF_FLOW_CONTEXT=1` (у `httpsprobe` — флаг `-flow-context`) запрос получает `connection_local` и `connection_remote`, адреса своего TCP-соединения. Через `s5client` `connection_local` совпадает с `remote` в `flow_open` клиентского flow с `leg` `application`, в режиме `plain` — с `remote` внешнего flow сервера; по `outer_flow` находится flow туннеля. Рекордер следит не более чем за 32 внешними сокетами сразу и после первых 32 берет не больше восьми новых в секунду, поэтому в инциденте есть не все запросы.

## Контекст ресурсов прогона

До и после каждого прогона `performance-ab.py` записывает `boot_id`, первую строку `/proc/stat`, `/proc/loadavg` и файлы собственной cgroup v2 по `/proc/self/cgroup`: `cpu.max`, `cpu.stat`, `cpu.pressure`, `memory.max`, `memory.current`, `memory.peak`, `memory.events`, `memory.pressure`. Недоступный источник попадает в `unavailable` с причиной. `cpu_interval` прогона — разность счетчиков `cpu.stat` и признак `throttled`: квота cgroup ограничивала CPU в этом интервале. При смене загрузки, cgroup или квоты и при сбросе счетчиков `cpu_interval` равен `unknown`. Интервал охватывает и запуск, и остановку прокси; CPU нагрузки берется из `resources.jsonl`. Квоты родительских cgroup driver не читает.

`environment.json` заменяется целиком после каждого шага, поэтому прерванная серия остается с `completed=false` и записями завершенных прогонов. После каждого прогона driver заново хеширует бинари; изменившийся вход проваливает прогон и серию.

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

## Длительный прогон

`scripts/performance-soak.py` готовит очередь сценариев `idle-tunnel`, `slow-read`, `stream` и `upload-stream` для режимов `obfs` и `wss` с включенной диагностикой и маркерами восстановления:

```bash
python3 scripts/performance-soak.py \
  --server /tmp/s5core-after --client /tmp/s5client-after --out /tmp/s5-soak
```

Без `--execute` скрипт только хеширует бинари и исходники `cmd/httpsprobe` и записывает `plan.json` в новый каталог. С `--execute`, только в Linux, он копирует прокси в каталог вывода, собирает тестовый бинарь `httpsprobe` и выполняет сценарии по одному, каждый в своей группе процессов. Унаследованные `S5_*`, `GODEBUG`, `GOFLAGS` и `GOMAXPROCS` отбрасываются: генератор получает `GOMAXPROCS=2`, прокси — значение Go по умолчанию. Сценарий — три цикла: нагрузка 30 минут в первом и 2 минуты в остальных (у `idle-tunnel` — удержание 8 туннелей по 2 минуты), после каждого 3 минуты восстановления, scrape раз в 15 с. Восемь сценариев занимают не меньше 288 минут без сборки и запуска; `--modes` и `--cases` сужают очередь. Очередь останавливается, если бинарь или исходник изменился до сборки либо копия прокси — перед очередным сценарием. `status` в `plan.json` — `prepared`, `running`, `completed` или `failed`.

## Профили и PGO

```bash
go build -tags=profiling -pgo=off -o /tmp/s5client-profile ./cmd/s5client
go build -tags=profiling -pgo=off -o /tmp/s5core-profile ./cmd/s5core
```

Только эти сборки читают `S5_PROFILE_DIR`, создавая `cpu`, `allocs`, `heap`, `mutex`, `block` и `goroutine` в отдельных файлах с правами 0600. Каталог должен быть новым для каждого процесса. Профили завершаются при штатном SIGTERM. HTTP pprof не публикуется; обычные релизные сборки не включают профилировщик. Ошибка или SIGKILL могут оставить неполный профиль. Профили сами меняют стоимость работы, поэтому A/B для выпуска выполняется без них.

Для PGO соберите отдельный профиль каждого бинаря после стабилизации кода, с распределением нагрузок рабочего маршрута. Сравните `go build -pgo=off` и `go build -pgo=/path/to/own/cpu.pprof` на независимой приемочной серии, сохраните время сборки и размер бинаря. Не переносите совмещенный профиль origin/генератора и не добавляйте лабораторный профиль как production `default.pgo`. Порог принятия из плана: минимум 3% и сохранение latency/memory-приемки.

## Граница приемки

Полный план включает настоящий arm64, рабочий WAN/VPS, quotas/revoke, UDP при потере, пики нагрузки и canary с откатом. Кросс-сборка ARM не заменяет эти испытания. Нельзя объявлять локальный результат выпуском. Результаты текущей реализации и непроверенные пункты перечислены в [отчете](../reports/performance-implementation-2026-09-22.md).
