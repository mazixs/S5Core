# Деградация связи помимо MTU

Исследование от 26.09.2026. Документ собран по внешним источникам: RFC, ITU-T, статьи с замерами, документация ядра Linux и OpenWrt, инженерные блоги. Это не аудит кода S5Core. Выводы для проекта вынесены в отдельные пометки. Проблемам MTU посвящен [`mtu.md`](mtu.md), диагностике - [`mtu-diagnostics.md`](mtu-diagnostics.md). Здесь собрано все, что портит качество связи по другим причинам или связано с MTU косвенно.

Пометки: [не подтверждено] - первичный источник не найден; [расчет] - арифметика автора документа по числам из источника; [вывод] - заключение автора, в источнике его нет. Номера в квадратных скобках ведут к списку источников в конце.

## Как отличить проблему MTU от всего остального

Проблема MTU зависит от **размера** пакета. Мелкие пакеты проходят, крупные теряются, причем детерминированно: теряется 100% пакетов больше MTU пути и 0% пакетов меньше него. Так продолжается, пока не изменить MTU или MSS. От нагрузки, времени суток и адресата это не зависит.

Остальные причины зависят от другого:

| Зависит от | Причины |
| --- | --- |
| нагрузки на канал | bufferbloat, полисинг, CPU роутера |
| времени и простоя | таймауты NAT, радиосостояния LTE, реконфигурация Starlink |
| адресата (IP, SNI, протокол) | DPI-дросселирование, блокировка UDP |
| среды | Wi-Fi, кабель, дуплекс, помехи |

Самая опасная ловушка: обрыв соединения DPI после первых килобайт выглядит в точности как черная дыра PMTUD. Как их различить, описано в разделе [4](#4-полисинг-шейпинг-и-dpi-дросселирование).

## 1. Bufferbloat и управление очередью

**Механизм.** Bufferbloat - это "the existence of excessively large and frequently full buffers inside the network" [1]. TCP с управлением перегрузкой по потерям заполняет буфер на узком месте до первой потери: аплинк модема, Wi-Fi, кольцо сетевой карты. Пока буфер наполняется, растет задержка. Большие буферы "damage or defeat" механизм избегания перегрузки [1].

Замеры Gettys и Nichols [1]:

- путь с RTT меньше 10 мс без нагрузки под нагрузкой давал больше 1,2 с;
- при аплинке 2 Мбит/с в полете было 500 КБ при BDP пути 2,5 КБ;
- типичный буфер кабельного модема 128-256 КБ. 128 КБ на аплинке 3 Мбит/с опустошаются за 340 мс, на 1 Мбит/с - около 1 с;
- кольцо сетевой карты на 256 пакетов при скорости Wi-Fi 1 Мбит/с дает до 3 с задержки. Если узкое место - Wi-Fi, очередь стоит на самом хосте.

**Симптом.** Без нагрузки RTT нормальный. Во время закачки, отдачи или бэкапа он вырастает до сотен миллисекунд или секунд. Игра и голос деградируют ровно тогда, когда кто-то качает. Как только нагрузка снята, проблема исчезает, поэтому тот, кто садится ее мерить, ее обычно не застает [1].

**Отличие от MTU.** Задержка растет у всех пакетов, включая ping, ACK и DNS, и только под нагрузкой.

**Как измерить.**

- Ping или UDP RTT во время насыщения канала в обе стороны.
- Flent RRUL: 4 TCP-потока вниз, 4 вверх, плюс ICMP и UDP RTT [9].
- Waveform, Cloudflare, LibreQoS, Apple `networkQuality` [8][11]. bufferbloat.net считает проблемой прирост задержки больше 50 мс или оценку ниже B [8].
- Метрика responsiveness (draft-ietf-ippm-responsiveness): RPM = 60000 / RTT в мс под рабочей нагрузкой. Шкала: Poor - 300 RPM (200 мс), Fair - 1000 (60 мс), Good - 6000 (10 мс) [10].

**Что помогает.**

- AQM. RFC 7567 (BCP 197): сетевые устройства SHOULD реализовывать AQM, он должен поддерживать ECN и не требовать ручной настройки [2].
- CoDel (RFC 8289): target 5 мс, interval 100 мс, рассчитан на RTT от 10 мс до 1 с [3].
- FQ-CoDel (RFC 8290): 1024 очереди, quantum 1514, limit 10240 пакетов. Разреженные потоки (ACK, DNS, SSH, VoIP, игровой UDP) получают неявный приоритет [4].
- CAKE: шейпер с компенсацией накладных линии, DiffServ и справедливостью по потокам и хостам [5].
- AQM работает, только если очередь образуется в роутере, а не в модеме. Поэтому SQM ставит шейпер ниже реальной скорости линии: OpenWrt советует начать с 90% от измеренного и подбирать [6]. Часто цитируемый диапазон 85-95% в первоисточнике не найден [не подтверждено].
- Накладные линии для шейпера [6][7]: ATM передает 48 байт данных в ячейке из 53; PPPoE - 8 байт; VDSL2 - 34 (26 без PPPoE); DOCSIS - 18 (+4 на VLAN). Если тип линии неизвестен, OpenWrt советует overhead 44 и mpu 96.
- Ограничения на роутере: SQM несовместим с аппаратным flow offloading [6]; когда cake не хватает CPU, растет задержка очереди [7].
- L4S (RFC 9330): средняя очередь меньше 1 мс и около 2 мс на p99. Для сравнения, у классического CC 5-20 мс в среднем, у PIE и FQ-CoDel 20-30 мс на p99 [12]. Нужны ECT(1), DualQ (RFC 9332) и масштабируемый CC. Comcast включил L4S в январе 2025 в шести городах [13], Apple поддерживает L4S с iOS 17 и macOS Sonoma [14].

**Для S5Core [вывод].** FQ на роутере видит внешние 5-tuple туннеля, а не внутренние потоки. Датаграммы игры по `0x83` едут внутри TCP-соединения ассоциации и делят его очередь. Native UDP `0x84` - отдельный разреженный UDP-поток, и fq_codel или cake дают ему приоритет sparse-потока.

## 2. Потери, джиттер и переупорядочивание

**Потери и TCP.**

- Формула Mathis: BW = (MSS / RTT) * C / sqrt(p) [15]. C = 1,22 при ACK на каждый пакет и 0,87 с delayed ACK.
- При MSS 1448 и RTT 50 мс один поток дает около 8,9 Мбит/с при 0,1% потерь и около 2,8 Мбит/с при 1% [расчет]. Процент потерь режет TCP с управлением по потерям сильнее любой настройки MTU. Полоса линейна по MSS: MSS 1360 вместо 1460 на тех же RTT и потерях дает около -6,8% [расчет].
- RFC 5681: быстрый повтор по 3 dupACK. По RTO окно падает до 1 сегмента, ssthresh = max(FlightSize/2, 2*SMSS) [16].
- Константы Linux: `TCP_RTO_MIN` 200 мс, начальный RTO 1 с (RFC 6298), `TCP_RTO_MAX` 120 с [37].

**Симптом потерь.** Скорость одного потока намного ниже канала, `ss -ti` показывает retrans. Если установка соединения иногда длится ровно на 1 с дольше обычного, потерялся SYN или SYN-ACK.

**Переупорядочивание.**

- Классический TCP принимает переставленные пакеты за потерю: 3 dupACK запускают ложный повтор и уменьшают окно [16].
- RACK-TLP (RFC 8985) определяет потерю по времени. Окно переупорядочивания по умолчанию min_RTT/4, но не больше SRTT; probe timeout 2*SRTT [17].
- Linux по умолчанию: `tcp_reordering` 3, `tcp_max_reordering` 300, `tcp_recovery` 0x1 (RACK), `tcp_early_retrans` 3 (TLP) [18].
- Источники переупорядочивания: балансировка по нескольким линкам, агрегация кадров в Wi-Fi, повторы HARQ в мобильных сетях.

**Джиттер и приложения реального времени.**

- ITU-T G.114: при планировании не превышать 400 мс в одну сторону, до 150 мс - "essentially transparent interactivity" [19].
- Source (Valve): интерполяция по умолчанию 100 мс (`cl_interp 0.1`) при tickrate 66, поэтому потеря одного snapshot не видна [20]. Страница открылась только через поиск.
- VALORANT (128 tick) держит буфер в один кадр движения на клиенте и в среднем полкадра на сервере, потому что "Packets often arrive late or sometimes not at all". Цель Riot - ping до 35 мс у 70% игроков [21].
- Правило: джиттер больше буфера интерполяции заметен как "телепортация", даже если медиана задержки хорошая.

**Отличие от MTU.** Потери случайны и почти не зависят от размера пакета: ping на 64 байта теряется так же, как на 1400.

**Как измерить.** `ss -ti` (rtt, rttvar, retrans, reordering), `nstat -az` (счетчики TcpExt с Reorder и retrans), mtr до конечного узла (с оговорками из раздела 9), `iperf3 -u` (jitter и loss). Всегда нужен контрольный путь без туннеля.

**Что помогает.** SACK и RACK-TLP (в Linux включены по умолчанию), BBR на путях со случайными потерями (раздел 8) и устранение причины на L1/L2 (раздел 7).

## 3. TCP поверх TCP и блокировка головы очереди

**TCP meltdown.** Так называют эффект, когда TCP заворачивают в TCP: у верхнего слоя таймаут короче, чем у нижнего, верхний ставит повторы быстрее, чем нижний успевает их доставить, и соединение глохнет [22]. OpenVPN прямо советует для туннеля UDP [22b].

Замеры Honda и др. (2005) [23]: TCP-туннель обычно снижает goodput вложенного TCP, но при большой задержке распространения может его улучшить. SACK снимает проблему, маленькие буферы сокетов ее усиливают.

**Почему CONNECT через L4-прокси сюда не попадает.** Прокси завершает TCP клиента и открывает свое соединение к цели. Это split connection по RFC 3135: "terminates the TCP connection received from an end system and establishes a corresponding TCP connection to the other end system" [24]. Два контура управления перегрузкой работают последовательно, а не один внутри другого [вывод]. Meltdown появляется, только если пользователь пускает через прокси собственный TCP-VPN или другой протокол со своими повторами.

**Блокировка головы очереди (HOL).** В одном TCP-потоке потеря сегмента задерживает все, что идет за ним. RFC 9114 пишет об этом для HTTP/2: "a lost or reordered packet causes all active transactions to experience a stall" [25].

**Для S5Core.** Это касается `0x83`: измеренная цена - в [`../benchmarks/udp-over-tcp.md`](../benchmarks/udp-over-tcp.md). Через туннель теряется меньше датаграмм, медиана не меняется, а платит хвост: плотный поток - один RTT, редкий - один RTO (в Linux минимум 200 мс). QUIC или WebRTC со своим CC поверх `0x83` по сути TCP-over-TCP: внутренний CC не видит потерь, но видит всплески задержки [вывод].

**Симптом.** UDP-приложение периодически замирает на 1 RTT или на 200+ мс, и только на пути с потерями.

**Отличие от MTU.** Паузы кратны RTT или RTO и совпадают со случайными потерями, а MTU дает полную остановку на крупных пакетах.

**Как измерить.** Один и тот же поток через `0x83` и через `0x84`, с netem-потерями и без (`scripts/udp_loss_matrix.sh`).

## 4. Полисинг, шейпинг и DPI-дросселирование

**Полисер и шейпер.** Полисер - token bucket, который отбрасывает все сверх лимита. Шейпер ставит лишнее в очередь, то есть превращает превышение в задержку.

Flach и др., SIGCOMM 2016 (270 млрд пакетов, 28 400 AS) [26]:

- полисинг найден у 2-7% соединений с потерями, в зависимости от региона;
- у полисированных соединений потери в среднем больше 20%, у остальных не больше 4,1%;
- видео под полисером во многих случаях проводит в rebuffering 15% времени и больше;
- профиль: высокая скорость, пока бакет не пуст, затем раунды повторов;
- рекомендуемые альтернативы: pacing на отправителе и шейпинг вместо полисинга.

**Симптомы.** У полисера быстрый старт, затем обвал и пила, много повторов, итоговая скорость ниже номинала. У шейпера скорость ровная, а RTT растет.

**DPI-дросселирование в России (зафиксированные случаи).**

- Twitter, с марта 2021 [27]. Триггер - SNI, лимит 130-150 кбит/с в обе стороны за счет отбрасывания пакетов. Состояние неактивной сессии живет около 10 минут. Фрагментированную TLS-запись дроссель не собирал.
- QUIC, март 2022: блокировка QUIC v1 при UDP-нагрузке от 1001 байта на порт 443 [28].
- YouTube, июль 2024: SNI `*.googlevideo.com`, TCP около 128 кбит/с, QUIC около 512 кбит/с [29].
- Cloudflare, с 9 июня 2025, крупные операторы: отдаются только первые 16 КБ, затем соединение замирает или рвется. Затронуты HTTP/1.1, HTTP/2 и HTTP/3 [30]. О том же сообщают для Hetzner, DigitalOcean и OVH [31].
- Весь UDP блокируют 3-5% сетей (RFC 9308) [32].

**Отличие от MTU - главная ловушка.** Обрыв после 16 КБ выглядит как черная дыра PMTUD: рукопожатие прошло, большой ответ висит. Различить можно так:

- уменьшение MSS помогает при MTU и не помогает при DPI;
- DPI зависит от адресата (IP, ASN, SNI): тот же объем с другого адреса проходит;
- дросселирование по SNI дает стабильный потолок скорости, а MTU - только "работает или нет".

Правило 1001 байта для QUIC в 2022 году тоже зависит от размера. Поэтому "QUIC не работает, TCP работает" требует проверки и размером, и портом (таблица в конце).

**Как измерить.** График скорости во времени, доля повторов в `ss -ti`, curl к одному IP с разным SNI, тот же запрос через туннель и напрямую, для QUIC - пакеты меньше и больше 1001 байта.

**Что помогает.** Против полисера - pacing (qdisc fq и BBR) [26]. Против DPI - шифрование, скрывающее SNI, и фрагментация первой записи [27]. UDP-транспорту нужен резервный путь по TCP.

## 5. NAT и CGNAT

**Таймауты привязок.**

- Стандарты. UDP по RFC 4787 REQ-5: не раньше 2 минут, рекомендовано 5 [33]. TCP established по RFC 5382: не меньше 2 ч 4 мин, transitory - не меньше 4 мин [34]. Те же 4 мин рекомендует RFC 7857 [35].
- Домашние шлюзы (34 устройства): UDP-таймауты отличаются на порядок, минимум 30 с, медиана 180 с. Половина устройств закрывает TCP-привязку меньше чем за час, одно - через 239 с [36].
- CGN: 74% закрывают простаивающий UDP за минуту или быстрее, разброс 10-200 с, медиана у сотовых 65 с, у проводных 35 с [38].
- RFC 9308 велит считать, что привязка может истечь через 30 с простоя [32]. WireGuard рекомендует PersistentKeepalive 25 с [39].
- Linux conntrack: `udp_timeout` 30 с, `udp_timeout_stream` 120 с, `tcp_timeout_established` 5 суток [40]. TCP keepalive по умолчанию начинается через 2 ч [18], для NAT это слишком поздно.

**Порты и адреса CGN.**

- RFC 6888: лимит портов на абонента, порт нельзя переиспользовать раньше 120 с [41].
- В поле абоненту выдают блоки портов: по 512 в трех AS, меньше 1K в шести, где-то 4K. При блоке 1K на один IP приходится 64 абонента [38].
- 21% CGN выдают разным сессиям одного абонента разные публичные IP [38].
- Переполнение conntrack на роутере пишет `nf_conntrack: table full, dropping packet`, и новые соединения не создаются [42].

**Симптом.** UDP-сессия умирает после паузы 30-120 с. Простаивающий туннель "висит": запись уходит в никуда. При множестве потоков не открываются новые соединения.

**Отличие от MTU.** Зависит от длительности простоя или числа соединений, а не от размера пакета.

**Как измерить.** Idle-проба с растущим интервалом (`scripts/keepalive_matrix.sh`, `cmd/idleprobe`), STUN до и после паузы, `nf_conntrack_count` против `nf_conntrack_max`.

**Для S5Core [вывод].** Интервал keepalive и так обязан быть меньше `READ_TIMEOUT` (30 с). Смена публичного адреса клиента посреди сессии - обычное дело для CGN, поэтому native UDP следует за адресом клиента по проверенным пакетам (раздел 10.6 [`../veil-spec.md`](../veil-spec.md)).

## 6. ECN и DSCP

**ECN.**

- ECN-зависимая связность у 0,42% IPv4-хостов: около 5 сайтов на 1000 получают лишнюю задержку установки даже при корректном откате. ECN согласуют 56% серверов на IPv4 и 65% на IPv6 [43].
- В ядре сети петля обратной связи ECN ломается в 40% случаев, обычно на границах AS [44].
- В QUIC коды ECN зеркалируют 20% хостов, валидацию проходят меньше 2%: мешают и сами провайдеры контента, и сеть, которая стирает биты [45].
- В Linux по умолчанию `tcp_ecn` = 2: ECN принимается на входящих соединениях, но не запрашивается на исходящих [18].
- RFC 8311 снял ограничения на эксперименты с ECN (ABE, L4S, ECN на SYN) [46].

**Симптом черной дыры ECN.** Часть хостов недоступна или соединяется с задержкой, только когда ECN запрошен. Меняет результат переключение `tcp_ecn`, а не размер пакета.

**DSCP.** Полное обнуление Diffserv чаще всего происходит на краю сети. Precedence bleaching превращает AF11/21/31/41 в DSCP 2. Сквозная доставка DSCP не гарантирована [47].

**Для S5Core [вывод].** На DSCP в интернете не опираться. Внутри туннеля DSCP приложения не виден, приоритет на своем роутере задается по внешним 5-tuple (порт native UDP, адрес сервера). Split-TCP в прокси не переносит ECN внутреннего соединения на внешнее, и L4S тоже.

## 7. Физика и L2

**Wi-Fi.**

- Среда общая: медленная станция съедает эфирное время остальных (performance anomaly). Добавляются очереди драйвера, энергосбережение и помехи.
- Airtime fairness и FQ-очереди в mac80211 (ath9k) дали на порядок меньшую задержку под нагрузкой и почти идеальную справедливость эфира [48]. AQL перенесен в mac80211 из ath10k и mt76 [49].
- Кампус, 47 точек доступа: на части точек больше 50% TCP-пакетов задерживаются на Wi-Fi-хопе дольше 20 мс, 10% - дольше 100 мс. Больше чем в половине случаев Wi-Fi-хоп дает больше 60% RTT [50].
- Статический режим энергосбережения округляет RTT до 100 мс, интервала beacon [51].
- Узкополосная помеха в 2,4 ГГц, в 1000 раз слабее сигнала, может сорвать связь [52].
- Симптом: джиттер 20-100+ мс, которого нет по кабелю, ступени RTT по 100 мс.
- Как измерить: ping шлюза по Wi-Fi и по кабелю, `iw dev <if> station dump` (retries, signal).
- Что помогает: кабель, 5 ГГц, драйверы с AQL, выключенное энергосбережение на игровом клиенте.
- MTU Wi-Fi не урезает: MSDU до 2304 байт, а мост в Ethernet оставляет 1500 (подробнее в [`mtu.md`](mtu.md)).

**LTE и 3G.**

- Замер в сети AT&T: переход из idle около 260 мс (у 3G - 582 мс), tail 11,6 с, long DRX 40 мс, DRX в idle 1,28 с [53].
- Цели спецификации LTE: переход idle -> connected меньше 100 мс, user plane меньше 5 мс; у 3G переход до 2 с [54].
- Каждый повтор HARQ в LTE FDD стоит 8 мс [55].
- Симптом: первый пакет после паузы медленнее на сотни мс. Как измерить: ping раз в 12+ с против ping раз в 200 мс.

**Starlink.** Синхронизированная реконфигурация раз в 15 с дает скачки задержки и провалы скорости. Bent-pipe около 40 мс, потери 4-8% на p75 [56]. Huston (APNIC, 2024): фоновые потери около 1%, задержка скачет с 30 до 80 мс, джиттер 6,7 мс [56b]. Симптом - периодичность 15 с на графике RTT. Потери на таком канале не означают проблем с размером пакета [вывод].

**Ethernet и кабель.**

- Несовпадение дуплекса: "extremely slow performance, intermittent connectivity", late collisions, растут счетчики FCS, CRC и runts. Плохой кабель "can be just good enough to connect... but corrupts packets" [57][58].
- Потери от порчи пакетов стабильны во времени и не зависят от загрузки [59].
- Отличие от MTU: теряются пакеты любого размера, хотя длинные кадры портятся чаще, и это проценты потерь, а не 100% отказ.
- Как измерить: `ethtool -S`, `ip -s link`.

**Микровсплески.** Главная причина потерь в ЦОД, p90 длительности меньше 200 мкс [60]. На посекундных графиках их не видно.

## 8. Хост и роутер

**CPU роутера.**

- RPS по умолчанию выключен: пакет обрабатывается на том CPU, куда пришло прерывание [61].
- В OpenWrt есть packet steering; по патчу для bcm53xx на одноядерных устройствах он ухудшает производительность [62].
- Software flow offloading дает в 2-3 раза больше полосы, hardware-вариант есть у MediaTek начиная с mt7621. Offloading работает для транзитного трафика, а не для процессов на самом роутере [63].
- Для клиента на роутере [вывод]: flow offloading его не ускоряет (трафик туннеля локальный), а аппаратный offload к тому же несовместим с SQM [6].
- Симптом: скорость упирается в одно значение, одно ядро 100% в sirq. Как измерить: `top`, `/proc/softirqs`, тот же тест с ПК за роутером.

**Offload-и сетевой карты.** С TSO/GSO/GRO tcpdump видит пакеты больше MTU [64][65]. Checksum offload дает ложные ошибки контрольных сумм [66]. Это частая причина искать несуществующую проблему MTU. Отключается через `ethtool -K <if> tso off gso off gro off` [64].

**Nagle и delayed ACK.** Delayed ACK в Linux длится от 40 до 200 мс [37]. Вместе с Nagle это дает паузу 200 мс и не больше 5 транзакций в секунду; лечится `TCP_NODELAY` и отправкой сообщения одной записью [67]. Go выключает Nagle на TCP-сокетах сам.

**Простой соединения.** После простоя дольше RTO окно сбрасывается [16]. В Linux `tcp_slow_start_after_idle` = 1 [18], поэтому пачка после паузы стартует медленно. Значение 0 на сервере часто советуют, но эффект в источниках не замерен [не подтверждено].

**Буферы и BDP.** Окно должно покрывать BDP: 400 Мбит/с * 43 мс около 2,15 МБ [расчет]. В Linux `tcp_rmem` по умолчанию растет до 32 МБ, `tcp_wmem` - до 4 МБ [18]. Окно меньше BDP - потолок одного потока.

**Управление перегрузкой.** BBR: при 0,1% потерь CUBIC теряет скорость в 10 раз и глохнет при потерях больше 1%, а BBR держит (1-p) до 5%; медианный RTT YouTube с BBR упал на 53% [68]. BBRv3 описан в draft-ietf-ccwg-bbr [69]. Один поток BBRv3 с ECN забирает больше 99% полосы против пяти потоков CUBIC [70] - справедливость между CC остается открытым вопросом.

**Установка соединения.** TCP Fast Open: 6% путей отбрасывают SYN с данными [71]. Happy Eyeballs v2: задержки 50 и 250 мс; IPv4 и IPv6 часто идут разными путями с разным качеством [72].

**Лимит ICMP.** В Linux `icmp_ratelimit` 1000 мс [18], но frag-needed ядро по скорости не ограничивает (подробнее в [`mtu.md`](mtu.md)). Роутеры на пути могут ограничивать ICMP, и тогда страдает PMTUD - это косвенная связь с MTU.

## 9. Ловушки измерения

- **Потери на промежуточном хопе mtr** - не проблема, если они не доходят до конца трассы: ICMP низкоприоритетен, обратные пути асимметричны [73]. Cisco ограничивает ICMP unreachable одним пакетом в 500 мс, отсюда звездочки на последнем хопе [74][75].
- **Многопоточный speedtest** открывает несколько потоков, а slow start занижает результат; NDT стабильно занижает на высоких скоростях [76]. Многопоточность прячет малое окно и потери, а туннель - это один поток. Сравнивайте `iperf3 -P 1` с `-P 8`.
- **Ping без нагрузки** не показывает bufferbloat. RRUL поэтому мерит RTT под нагрузкой [9].
- **Offload на хосте** искажает захват пакетов (раздел 8).
- **Среднее вместо хвоста.** Микровсплески и HOL видны только в p99, а игре важен именно хвост.
- **Нет контроля.** Число без контроля по тому же пути мимо туннеля ничего не значит. netem не воспроизводит CGNAT и CDN.
- **Эффект наблюдателя.** Bufferbloat исчезает, как только нагрузку останавливают ради проверки [1].

## Таблица: симптом, причина, проверка

| Симптом | Причина MTU | Причина не MTU | Как проверить |
| --- | --- | --- | --- |
| Рукопожатие прошло, большой ответ висит | черная дыра PMTUD, нет MSS clamping | DPI-обрыв после 16 КБ [30], полисер | уменьшить MSS: помогло - MTU; другой IP или SNI проходит, или обрыв около 16 КБ при любом MSS - DPI |
| Мелкий ping с DF проходит, крупный нет | да | - | `ping -M do -s` с шагом |
| QUIC не работает, TCP работает | QUIC нужно от 1200 байт UDP-нагрузки [77] | UDP закрыт [32], DPI от 1001 байта [28] | размер Initial, UDP на другой порт |
| Задержка растет только под закачкой | - | bufferbloat | RRUL, networkQuality, ping шлюза под нагрузкой |
| Быстрый старт, обвал, пила | - | полисер [26] | скорость во времени, `ss -ti` |
| Ровный потолок на одном сервисе | - | DPI по SNI [27][29] | другой SNI, туннель и напрямую |
| Один поток медленный, speedtest хороший | - | потери, окно меньше BDP | `iperf3 -P 1` против `-P 8` |
| UDP умирает после паузы 30-120 с | - | таймаут NAT [36][38] | idle-проба, STUN |
| Туннель висит после простоя | - | таймаут TCP-привязки | keepalive меньше 30 с |
| Новые соединения не открываются | - | порты CGN, conntrack полон [42] | `dmesg`, `nf_conntrack_count` |
| Джиттер 20-100+ мс, по кабелю нет | - | Wi-Fi [50] | ping шлюза, `iw station dump` |
| Ступени RTT по 100 мс | - | энергосбережение Wi-Fi [51] | выключить power save |
| Всплески каждые 15 с | - | Starlink [56] | периодичность RTT |
| Первый пакет после паузы медленнее | - | радиосостояния LTE [53] | редкий ping против частого |
| Паузы ровно 40 или 200 мс | - | Nagle и delayed ACK [67] | tcpdump, `TCP_NODELAY` |
| Установка иногда дольше на 1 с | - | потеря SYN, TFO [71] | tcpdump: повтор SYN |
| Потери не зависят от загрузки | частично | кабель, дуплекс, помехи [57][59] | `ethtool -S`, `ip -s link` |
| Потолок скорости, одно ядро в sirq | - | CPU роутера [63] | `top`, `/proc/softirqs` |
| Игра дергается при закачке через `0x83` | - | HOL и bufferbloat | тот же поток через `0x84`, SQM |
| Часть сайтов "случайно" медленные | - | Happy Eyeballs [72], ECN [43] | `curl -4` и `curl -6`, `tcp_ecn` |
| Потери на промежуточном хопе mtr | - | лимит ICMP [73][74] | смотреть последний хоп |
| Пакеты больше MTU, bad checksum в захвате | ложный сигнал | offload [64][66] | `ethtool -K ... off` |

## Источники

1. Gettys, Nichols, "Bufferbloat: Dark Buffers in the Internet", ACM Queue, 2011: https://queue.acm.org/detail.cfm?id=2071893 , https://web.mit.edu/6.033/2017/wwwdocs/papers/gettys.pdf
2. RFC 7567: https://www.rfc-editor.org/rfc/rfc7567.html
3. RFC 8289: https://www.rfc-editor.org/rfc/rfc8289.html
4. RFC 8290: https://www.rfc-editor.org/rfc/rfc8290.html
5. Høiland-Jørgensen и др., "Piece of CAKE", 2018: https://arxiv.org/abs/1804.07617
6. OpenWrt, SQM: https://openwrt.org/docs/guide-user/network/traffic-shaping/sqm
7. OpenWrt, SQM details: https://openwrt.org/docs/guide-user/network/traffic-shaping/sqm-details
8. bufferbloat.net, Tests for Bufferbloat: https://www.bufferbloat.net/projects/bloat/wiki/Tests_for_Bufferbloat/
9. Flent, тесты: https://flent.org/tests.html
10. draft-ietf-ippm-responsiveness: https://datatracker.ietf.org/doc/draft-ietf-ippm-responsiveness/
11. Apple, networkQuality: https://support.apple.com/en-us/101942
12. RFC 9330: https://www.rfc-editor.org/rfc/rfc9330.html
13. Comcast L4S, RCR Wireless, 2025: https://www.rcrwireless.com/20250129/uncategorized/comcast-l4s
14. Apple, L4S: https://developer.apple.com/documentation/network/testing-and-debugging-l4s-in-your-app
15. Mathis, Semke, Mahdavi, Ott, CCR, 1997: https://www.cs.utexas.edu/~lam/395t/papers/Mathis1998.pdf
16. RFC 5681: https://www.rfc-editor.org/rfc/rfc5681.html
17. RFC 8985: https://www.rfc-editor.org/rfc/rfc8985.html
18. Linux, ip-sysctl: https://docs.kernel.org/networking/ip-sysctl.html
19. ITU-T G.114: https://www.itu.int/rec/t-rec-g.114-200305-i
20. Valve, Source Multiplayer Networking: https://developer.valvesoftware.com/wiki/Source_Multiplayer_Networking
21. Riot Games, "Peeking into VALORANT's Netcode": https://www.riotgames.com/en/news/peeking-valorants-netcode
22. O. Titz, "Why TCP Over TCP Is A Bad Idea", 2001 (страница сейчас недоступна): http://sites.inka.de/bigred/devel/tcp-tcp.html
22b. OpenVPN, FAQ TCP meltdown: https://openvpn.net/as-docs/faq-tcp-meltdown.html
23. Honda и др., ITCom 2005: https://lsnl.jp/~ohsaki/papers/Honda05_ITCom.pdf
24. RFC 3135: https://www.rfc-editor.org/rfc/rfc3135.html
25. RFC 9114: https://www.rfc-editor.org/rfc/rfc9114.html
26. Flach и др., "An Internet-Wide Analysis of Traffic Policing", SIGCOMM 2016: http://www.columbia.edu/~ebk2141/papers/policing-sigcomm16.pdf
27. Xue и др., "Throttling Twitter", IMC 2021: https://censoredplanet.org/assets/throttling-imc-paper.pdf
28. ValdikSS, рассылка IETF QUIC, 2022: https://www.mail-archive.com/quic@ietf.org/msg02033.html
29. net4people, issue 382: https://github.com/net4people/bbs/issues/382
30. Cloudflare, 2025: https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/
31. net4people, issue 490: https://github.com/net4people/bbs/issues/490
32. RFC 9308: https://www.rfc-editor.org/rfc/rfc9308.html
33. RFC 4787: https://www.rfc-editor.org/rfc/rfc4787.html
34. RFC 5382: https://www.rfc-editor.org/rfc/rfc5382.html
35. RFC 7857: https://www.rfc-editor.org/rfc/rfc7857.html
36. Hätönen и др., IMC 2010: https://conferences.sigcomm.org/imc/2010/papers/p260.pdf
37. Linux, include/net/tcp.h: https://github.com/torvalds/linux/blob/master/include/net/tcp.h
38. Richter и др., IMC 2016: https://arxiv.org/pdf/1605.05606
39. WireGuard, quickstart: https://www.wireguard.com/quickstart/
40. Linux, nf_conntrack-sysctl: https://docs.kernel.org/networking/nf_conntrack-sysctl.html
41. RFC 6888: https://www.rfc-editor.org/rfc/rfc6888.html
42. SUSE KB 000020149: https://www.suse.com/support/kb/doc/?id=000020149
43. Trammell и др., PAM 2015: https://mirja.kuehlewind.net/paper/ecn-pam15.pdf
44. Bauer и др., IMC 2011: https://conferences.sigcomm.org/imc/2011/docs/p171.pdf
45. ECN в QUIC, 2023: https://arxiv.org/abs/2309.14273
46. RFC 8311: https://www.rfc-editor.org/rfc/rfc8311.html
47. RFC 9435: https://www.rfc-editor.org/rfc/rfc9435.html
48. Høiland-Jørgensen и др., "Ending the Anomaly", USENIX ATC 2017: https://arxiv.org/abs/1703.00064
49. LWN, AQL: https://lwn.net/Articles/802351/
50. Pei и др., INFOCOM 2016: https://1989chenguo.github.io/Publications/WiLy-INFOCOM16.pdf
51. Krashinsky, Balakrishnan, MobiCom 2002: https://www.sigmobile.org/mobicom/2002/papers/p059-krashinsky.pdf
52. Gummadi и др., 2007: https://pdfs.semanticscholar.org/8e20/606b50cea1200ff52060a80f417aa8a359ee.pdf
53. Huang и др., MobiSys 2012: https://feng-qian.github.io/paper/lte_mobisys12.pdf
54. I. Grigorik, High Performance Browser Networking, Mobile Networks: https://hpbn.co/mobile-networks/
55. HARQ в LTE: https://arxiv.org/pdf/1808.07034
56. Starlink, WWW 2024: https://arxiv.org/pdf/2310.09242
56b. G. Huston, "A transport protocol's view of Starlink", APNIC, 2024: https://blog.apnic.net/2024/05/17/a-transport-protocols-view-of-starlink/
57. Cisco, duplex mismatch: https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/12027-53.html
58. Shalunov, Carlson, PAM 2005: https://link.springer.com/chapter/10.1007/978-3-540-31966-5_11
59. Zhuo и др., SIGCOMM 2017: https://dl.acm.org/doi/10.1145/3098822.3098849
60. Zhang и др., IMC 2017: https://conferences.sigcomm.org/imc/2017/papers/imc17-final60.pdf
61. Linux, scaling: https://docs.kernel.org/networking/scaling.html
62. OpenWrt, патч packet steering: https://lists.openwrt.org/pipermail/openwrt-devel/2022-June/038808.html
63. OpenWrt, flow offloading: https://openwrt.org/docs/guide-user/perf_and_log/flow_offloading
64. Red Hat, offload и tcpdump: https://access.redhat.com/solutions/43888
65. Linux, segmentation offloads: https://docs.kernel.org/networking/segmentation-offloads.html
66. Wireshark, TCP checksum verification: https://wiki.wireshark.org/TCP_Checksum_Verification
67. S. Cheshire, Nagle и delayed ACK: http://www.stuartcheshire.org/papers/NagleDelayedAck/
68. Cardwell и др., BBR, 2016: https://web.stanford.edu/class/cs244/papers/bbr.pdf
69. draft-ietf-ccwg-bbr: https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/
70. Zeynali и др., ANRW 2024: https://balakrishnanc.github.io/papers/zeynali-anrw2024.pdf
71. RFC 7413: https://www.rfc-editor.org/rfc/rfc7413.html
72. RFC 8305: https://www.rfc-editor.org/rfc/rfc8305.html
73. APNIC, чтение traceroute и mtr, 2022: https://blog.apnic.net/2022/03/28/how-to-properly-interpret-a-traceroute-or-mtr/
74. Cisco, traceroute: https://www.cisco.com/c/en/us/support/docs/ip/ip-routed-protocols/22826-traceroute.html
75. NANOG 47, traceroute: https://archive.nanog.org/sites/default/files/10_Roisman_Traceroute.pdf
76. Feamster, Livingood, 2019: https://arxiv.org/pdf/1905.02334
77. RFC 9000, раздел 14: https://www.rfc-editor.org/rfc/rfc9000.html#section-14

Оговорки: страницы ACM, Valve и Waveform при сборе отдавали 403, факты по Valve взяты из выдачи поиска. Первоисточником не подтверждены диапазон 85-95% для SQM, пороги оценок Waveform и эффект `tcp_slow_start_after_idle=0`.
