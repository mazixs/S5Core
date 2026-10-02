# Диагностика MTU: поведение ОС, инструменты и методика

Исследование от 26.09.2026, дополняет [`mtu.md`](mtu.md). Документ отвечает на три вопроса:

- как ОС и библиотеки обращаются с размером пакета;
- какими командами найти предел пути;
- как по шагам отличить проблему MTU от черной дыры и от проблем, не связанных с MTU.

Что портит связь помимо MTU, описано в [`path-degradation.md`](path-degradation.md).

Что проверено:

- сверено с документацией kernel.org, man7.org, исходниками Linux, XNU, FreeBSD, Go и quic-go, Microsoft Learn и RFC;
- пометкой [лаб] отмечены пункты, проверенные опытом на Linux 7.0 и Go 1.26 в сетевых пространствах без root. Стенд приведен в [разделе 7](#стенд-без-root);
- [не подтверждено] - первоисточник не найден.

## Кратко

- В Linux предел пути хранится в кеше маршрута 600 с. Смотреть его командой `ip route get <адрес>`, искать - командой `ping -M probe -s N` или `tracepath`.
- UDP-сокет по умолчанию (режим `WANT`) после ICMP молча фрагментирует датаграммы, а не возвращает ошибку. Стандартная библиотека Go режим не меняет. udp(7) описывает это неверно, см. [раздел 8](#8-противоречия-в-документации).
- `tcp_mtu_probing` в Linux по умолчанию выключен (0). [лаб] В черной дыре выгрузка 2 МБ не завершилась за 40 с, при значении 1 заняла 12,2 с, при значении 2 - 0,01 с.
- macOS распознает черную дыру сама. FreeBSD по умолчанию не распознает. Про Windows источники противоречат друг другу.
- Если ping мелкими пакетами проходит, это ничего не доказывает. Черная дыра видна только на пробах с DF размером около предела и при tcpdump на отправителе.
- Кадр больше MRU в том же L2 теряется без ICMP вообще. Его видно только в счетчиках `RX dropped` [лаб].

## 1. Арифметика размеров

Данные ICMP echo (`ping -s`) = MTU - 28 для IPv4 и MTU - 48 для IPv6. MSS = MTU - 40 для IPv4 и MTU - 60 для IPv6. Полезная нагрузка UDP равна данным ICMP echo.

| IP MTU | Где встречается | `ping -s`, IPv4 | `ping -s`, IPv6 | MSS, IPv4 | MSS, IPv6 |
| --- | --- | --- | --- | --- | --- |
| 1500 | Ethernet, IPoE | 1472 | 1452 | 1460 | 1440 |
| 1492 | PPPoE | 1464 | 1444 | 1452 | 1432 |
| 1480 | IPIP, 6in4, MAP-T | 1452 | 1432 | 1440 | 1420 |
| 1460 | DS-Lite, MAP-E, L2TP, GCP | 1432 | 1412 | 1420 | 1400 |
| 1450 | VXLAN, Hetzner Cloud Networks | 1422 | 1402 | 1410 | 1390 |
| 1428 | Verizon по умолчанию | 1400 | 1380 | 1388 | 1368 |
| 1420 | WireGuard (wg-quick) | 1392 | 1372 | 1380 | 1360 |
| 1400 | туннели Azure, GRE+IPsec | 1372 | 1352 | 1360 | 1340 |
| 1380 | Mullvad | 1352 | 1332 | 1340 | 1320 |
| 1358 | рекомендация 3GPP | 1330 | 1310 | 1318 | 1298 |
| 1280 | минимум IPv6, Tailscale, WARP | 1252 | 1232 | 1240 | 1220 |

Датаграмма native UDP S5Core длиной 1400 байт (`MaxWire`) требует PMTU не меньше 1428 по IPv4 и 1448 по IPv6. Проверить путь под этот размер можно так: `ping -M probe -s 1400` и `ping -6 -M probe -s 1400`.

## 2. Linux

### 2.1 Где лежит PMTU

- С версии 3.6 PMTU хранится как исключение маршрута (FIB nexthop exception). Константы из `net/ipv4/route.c` [1]:
  - `DEFAULT_MTU_EXPIRES` = 600 с;
  - `DEFAULT_MIN_PMTU` = 552;
  - `DEFAULT_MIN_ADVMSS` = 256.
- Функция `__ip_rt_update_pmtu` меняет PMTU не всегда:
  - закрепленный (`lock`) маршрут и увеличение PMTU она игнорирует;
  - значение меньше `min_pmtu` превращает в 552, закрепляет маршрут, и DF с этого момента не ставится.
- В IPv6 (`net/ipv6/route.c`) PMTUD отключить нельзя: "IPv6 pmtu discovery isn't optional, so 'mtu lock' cannot disable it". PTB со значением меньше 1280 отбрасывается [2][RFC 8201, разд. 5.2].

```bash
ip route get 203.0.113.10          # "cache expires 599sec mtu 1400"
ip route show cache                # IPv4-исключения, снова работает с 5.3
ip -6 route show cache
ip route flush cache               # сбросить перед повторной пробой
```

[лаб] После Frag Needed от роутера с MTU 1400 команда выводит `10.2.0.2 via 10.1.0.1 dev a0 src 10.1.0.2 uid 0 / cache expires 599sec mtu 1400`.

### 2.2 Маршрут и sysctl

Настройки маршрута (ip-route(8)) [3]:

- `mtu lock N` - "no path MTU discovery will be tried, all packets will be sent without the DF bit in IPv4 case or fragmented to MTU for IPv6";
- `advmss N` - MSS в собственных SYN. Без него MSS считается из MTU устройства первого хопа.

```bash
ip route add 203.0.113.0/24 via 192.0.2.1 mtu lock 1400
ip route change default via 192.0.2.1 advmss 1360
```

Параметры sysctl [4]:

- `net.ipv4.ip_no_pmtu_disc`, по умолчанию 0:
  - 1 - после Frag Needed ставится `min(old, min_pmtu)`;
  - 2 - входящие PMTU-сообщения отбрасываются, каждый сокет получает `IP_PMTUDISC_DONT`;
  - 3 - события PMTU учитываются только для TCP и SCTP.
- `net.ipv4.route.min_pmtu` = 552, `mtu_expires` = 600 с (в документации значения нет, оно взято из кода).
- `net.ipv4.tcp_mtu_probing`, по умолчанию 0:
  - 1 - "Disabled by default, enabled when an ICMP black hole detected";
  - 2 - "Always enabled, use initial MSS of tcp_base_mss".
- Остальное из `include/net/tcp.h`: `tcp_base_mss` = 1024, `tcp_mtu_probe_floor` = 48, `tcp_min_snd_mss` = 48, `tcp_probe_interval` = 600 с, `tcp_probe_threshold` = 8.
- **Как ядро распознает черную дыру** (`tcp_timer.c`, `tcp_mtu_probing()`):
  - срабатывает по истечении `tcp_retries1`;
  - в первый раз только включает пробы;
  - в следующие разы ставит MSS равным половине `search_low`, не больше `tcp_base_mss` и не меньше `probe_floor` и `min_snd_mss`.
- В IPv6 `conf/*/mtu` не бывает меньше 1280. `accept_ra_mtu` применяет MTU из Router Advertisement.

### 2.3 Режимы сокета

Значения `IP_MTU_DISCOVER` [5]:

| Режим | Значение | Поведение |
| --- | --- | --- |
| `DONT` | 0 | DF не ставится никогда |
| `WANT` | 1 | по умолчанию. Датаграмма помещается в PMTU - DF ставится, не помещается - ядро фрагментирует ее само и без ошибки |
| `DO` | 2 | DF всегда, датаграмма больше PMTU - `EMSGSIZE` |
| `PROBE` | 3 | DF, кеш PMTU игнорируется. Режим для DPLPMTUD |
| `INTERFACE` | 4 | размер по MTU интерфейса без DF, входящие Frag Needed игнорируются |
| `OMIT` | 5 | как `INTERFACE`, но пакет больше MTU интерфейса фрагментируется |

- У IPv6 те же значения (`IPV6_MTU_DISCOVER` = 23), плюс `IPV6_MTU` = 24 и `IPV6_DONTFRAG` = 62.
- Значение по умолчанию задает `inet_create`: `WANT`, а при `ip_no_pmtu_disc` - `DONT`. У IPv6 всегда `WANT`.
- `IP_MTU` доступен только через `getsockopt` и только на подключенном сокете: `connect`, затем чтение дает начальную оценку [6].
- **Асинхронная ошибка.** После Frag Needed ядро обновляет PMTU и, если режим не `DONT`, ставит сокету `EMSGSIZE` (`__udp4_lib_err`):
  - без `IP_RECVERR` ошибку увидит только подключенный сокет, при следующем вызове;
  - с `IP_RECVERR` она ложится в `MSG_ERRQUEUE`, и `ee_info` содержит найденный MTU (`SO_EE_ORIGIN_ICMP`) [7].
- **UDP GSO** (`UDP_SEGMENT`, с 4.18) и GRO (с 5.0). Размер сегмента больше пути дает `EMSGSIZE`, превышение числа сегментов - `EINVAL` [8].

### 2.4 Счетчики

```bash
nstat -az | grep -E 'IpFrag|IpReasm|Ip6Frag|Ip6Reasm|IcmpInDestUnreachs|Icmp6(In|Out)PktTooBigs|TCPMTUP'
ss -tin dst 203.0.113.10           # mss:1448 pmtu:1500 rcvmss:1448 advmss:1448
ip -s -s link show dev eth0        # RX dropped, length errors
ethtool -S eth0 --groups eth-mac rmon   # FrameTooLongErrors, etherStatsJabbers
```

| Счетчик | О чем говорит |
| --- | --- |
| `IpFragFails` | роутер получил пакет с DF больше MTU и отправил Frag Needed |
| `IpFragOKs`, `IpFragCreates` | ОС сама фрагментирует исходящие |
| `IpReasmOKs`, `IpReasmFails`, `IpReasmTimeout` | сборка у получателя |
| `IcmpInDestUnreachs` | все ICMP unreachable. Отдельного счетчика для кода 4 в Linux нет |
| `Icmp6InPktTooBigs` | пришли PTB |
| `TcpExtTCPMTUPSuccess`, `TCPMTUPFail` | пробы PLPMTUD |
| `rx_length_errors` NIC | включает `aFrameTooLongErrors` [9] |

[лаб] Кадр 1500 уходит на интерфейс с MTU 1400 в том же L2. Потеря 100%, на приемнике растет `RX dropped`, `errors` остается 0, ICMP нет.

У tun-устройства MTU по умолчанию 1500 (`drivers/net/tun.c`).

## 3. Инструменты

### ping

Режимы `-M` в iputils [10]:

- `do` - DF с учетом кеша PMTU;
- `want` - фрагментировать локально;
- `probe` - DF в обход кеша;
- `dont` - без DF.

`-s` по умолчанию 56.

```bash
LC_ALL=C ping -c3 -M do -s 1472 203.0.113.10       # ответ "Frag needed and DF set (mtu = N)"
LC_ALL=C ping -c3 -M probe -s 1472 203.0.113.10    # в обход кеша, ICMP приходит снова
ping -6 -c3 -M do -s 1452 2001:db8::10
for s in 1472 1464 1452 1432 1400 1372 1330 1252; do
  ping -c2 -W1 -M probe -s $s 203.0.113.10 >/dev/null && echo "$s ok" || echo "$s fail"
done
```

[лаб] Путь через роутер с MTU 1400:

- первый `-M do -s 1472` получает `From 10.1.0.1 ... Frag needed and DF set (mtu = 1400)`;
- повтор отказывает сразу, `ping: sendmsg: Message too long`, на провод пакет не уходит. Это кеш PMTU, а не сеть;
- `-M probe` снова доходит до роутера и снова получает ICMP;
- `-s 1372` проходит.

На других ОС:

- Windows: `ping -f -l 1472 host`. `/f` ставит DF, только для IPv4 [11];
- FreeBSD и macOS: `ping -D -s 1472 host` [12].

### tracepath, traceroute, mtr

- tracepath(8) работает по UDP без root и выводит pmtu каждого хопа с итогом `Resume: pmtu N hops X back Y` [13]. [лаб] Пример вывода: `1?: [LOCALHOST] pmtu 1500` ... `2: 10.1.0.1 pmtu 1400` ... `Resume: pmtu 1400 hops 2 back 2`.
- `traceroute --mtu` ставит DF и выводит `F=NUM` [14].
- В mtr `-s` задает размер вместе с заголовками IP и ICMP. Опции DF в man нет [15].

```bash
tracepath -n 203.0.113.10
tracepath -6 -n 2001:db8::10
traceroute --mtu -n 203.0.113.10
mtr -n -r -c 50 -s 1400 203.0.113.10
```

### Прочие

- **nmap `path-mtu`**: TCP или UDP с DF, вывод вида `1492 <= PMTU < 1500` [16].
- **scamper** [17]:
  - `trace -M` делает PMTUD после traceroute;
  - `tbit -t pmtud` проверяет, как сервер распознает черную дыру;
  - надежнее методы UDP и TCP ACK: ICMP может приписать хопу проблему обратного пути.
- **iperf3** [18]:
  - `-M` задает MSS;
  - `--dont-fragment` ставит DF для UDP по IPv4;
  - `-l` задает размер датаграммы.

```bash
nmap --script path-mtu -p 443 203.0.113.10
scamper -I "trace -P udp-paris -M 203.0.113.10"
iperf3 -c 203.0.113.10 -u -b 50M -l 1400 --dont-fragment
iperf3 -c 203.0.113.10 -M 1360
```

### tcpdump и Wireshark

```bash
tcpdump -ni any 'icmp[icmptype] == icmp-unreach and icmp[icmpcode] == 4'   # Frag Needed
tcpdump -ni any 'icmp6 and ip6[40] == 2'          # PTB (без extension headers)
tcpdump -ni any 'ip[6:2] & 0x3fff != 0'           # фрагменты IPv4
tcpdump -ni any 'ip6 protochain 44'               # фрагменты IPv6
tcpdump -ni wan -v 'tcp[tcpflags] & tcp-syn != 0' # "mss N" в SYN и SYN-ACK
tcpdump -ni any 'udp and greater 1400'            # крупные датаграммы
```

Поля Wireshark: `tcp.options.mss_val`, `tcp.analysis.retransmission`, `ip.flags.df`, `ip.flags.mf`, `ip.frag_offset`, `icmp.type==3 && icmp.code==4`, `icmp.mtu`, `icmpv6.type==2`, `icmpv6.mtu` [19].

**Как черная дыра выглядит в pcap:** крупные сегменты с DF повторяются с растущим RTO, ICMP не приходит, а мелкие пакеты и ACK идут.

### Внешние проверки

- test-ipv6.com: в FAQ отдельно сказано, что ICMPv6 type 2 должен пропускаться [20].
- RIPE Atlas: у traceroute есть `--size` и `--dont-fragment`. У ping DF нет [21].

```bash
ripe-atlas measure traceroute --target 203.0.113.10 --size 1400 --dont-fragment
```

- icmpcheck.popcount.org 26.09.2026 отвечал HTTP 503 [не подтверждено, что сервис жив].

## 4. Другие ОС и роутеры

### Windows

- `EnablePMTUBHDetect` (Tcpip\Parameters, по умолчанию 0) - после нескольких неподтвержденных повторов TCP шлет пакеты без DF и снижает MSS. `EnablePMTUDiscovery` (по умолчанию 1) при значении 0 ставит 576 для нелокальных адресов. Оба ключа описаны в документации Windows 2000 и 2003 [22].
- По блогу Microsoft 2006 года, в Vista распознавание черных дыр включено по умолчанию [23]. Действует ли ключ в современной Windows - [не подтверждено].

```powershell
netsh interface ipv4 show subinterfaces
netsh interface ipv4 set subinterface "Ethernet" mtu=1400 store=persistent
Get-NetIPInterface | ft ifAlias,AddressFamily,NlMtu
Set-NetIPInterface -InterfaceAlias "Ethernet" -NlMtuBytes 1400
```

- quic-go на Windows ставит `IP_DONTFRAGMENT` и `IPV6_DONTFRAG`. `WSAEMSGSIZE` приходит и при отправке, и при чтении в слишком маленький буфер [24].

### macOS и iOS

Из XNU, `bsd/netinet/tcp_timer.c` [25]:

- `net.inet.tcp.pmtud_blackhole_detection` = 1, `pmtud_blackhole_mss` = 1200;
- в состоянии ESTABLISHED на втором RTO ядро снимает DF и ставит MSS 1200. Если повторы продолжаются (больше 4), откатывает;
- `mssdflt` = 512, `v6mssdflt` = 1024.

```bash
sysctl net.inet.tcp.pmtud_blackhole_detection net.inet.tcp.pmtud_blackhole_mss
ping -D -s 1472 203.0.113.10
```

MTU вручную: System Settings > Network > Details > Hardware > Configure Manually [26].

### FreeBSD

`net.inet.tcp.pmtud_blackhole_detection` по умолчанию 0 [27]:

- 1 - оба семейства, 2 - только IPv4, 3 - только IPv6;
- MSS после распознавания: 1200 для IPv4, 1220 для IPv6.

### Android

- `VpnService.Builder.setMtu`: "If it is not set, the default value in the operating system will be used" [28]. JNI задает MTU только при `mtu > 0`, поэтому у tun приложения, не задавшего MTU, остается 1500.
- MTU сотовой сети Android берет из PCO, затем из APN, затем из overlay по MCC/MNC. Для IPv6 - еще из RA [29].

### Роутеры

- **OpenWrt**: `mtu_fix` в зоне firewall ("Enable MSS clamping"), по умолчанию 1 на wan и 0 на lan. MTU интерфейса задается опцией `mtu` в `network` [30].
- **nftables** (ядро 4.14+, nft 0.9) [31]:

  ```bash
  nft add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu
  nft add rule inet filter forward tcp flags syn tcp option maxseg size set 1452
  ```

- **iptables**: `-A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu` [32].
- **MikroTik**: `change-tcp-mss` в PPP-профиле или `action=change-mss new-mss=clamp-to-pmtu` в mangle [33].
- **Keenetic**: `interface <name> ip mtu` [34].
- **Во всех случаях clamping переписывает только TCP SYN и SYN-ACK.** Правило в FORWARD не касается соединений самого роутера: их MSS берется из MTU исходящего интерфейса или из `advmss` маршрута [3].
- **wg-quick** без `MTU=` берет mtu из `ip route get <endpoint>`, иначе у маршрута по умолчанию, иначе 1500, и вычитает 80 (`set_mtu_up` в `linux.bash`) [35].

## 5. Приложения и библиотеки

### Go

- `src/net/sockopt_linux.go` у датаграммных сокетов ставит только `IPV6_V6ONLY` и `SO_BROADCAST`. Опций DF и PMTU нет ни в `net`, ни в `internal/poll`, поэтому действует умолчание ядра `WANT` [36].
- [лаб] UDP-сокет Go на интерфейсе с MTU 1500:

  | Режим | Данные | Результат |
  | --- | --- | --- |
  | по умолчанию (`IP_MTU_DISCOVER` = 1) | 1400 | DF, проходит |
  | по умолчанию | 1473 | молча фрагментирован на 1500 + 21 без DF, `IpFragCreates` +2 |
  | `IP_PMTUDISC_DO` | 1473 | `write: message too long`, `errors.Is(err, syscall.EMSGSIZE)` = true |
  | `IP_PMTUDISC_PROBE` | 1473 | `EMSGSIZE` по MTU интерфейса |

- Режим ставится через `RawConn.Control`:

  ```go
  rc, _ := conn.SyscallConn()
  rc.Control(func(fd uintptr) {
      unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
      unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_PROBE)
  })
  ```

### quic-go (v0.63.0)

Источник [24]:

- на Linux ставит `IP_PMTUDISC_PROBE` и `IPV6_PMTUDISC_PROBE` (`sys_conn_df_linux.go`);
- `InitialPacketSize` = 1280, `MinInitialPacketSize` = 1200, `MaxPacketBufferSize` = 1452;
- `Config.InitialPacketSize` ограничен диапазоном [1200, 1452];
- DPLPMTUD устроен как бинарный поиск с шагом до 20 байт и пробой каждые 5 RTT. После 3 потерянных проб подряд размер недостижим. Сверху поиск ограничивает `max_udp_payload_size` пира;
- `DisablePathMTUDiscovery` доступен только там, где можно поставить DF.

### Другие

- **Hysteria 2**: `MaxDatagramFrameSize` = 1200, собственная фрагментация UDP до 4096 байт, опция `quic.disablePathMTUDiscovery` [37].
- **TUIC v5**: в пакете есть `FRAG_TOTAL` и `FRAG_ID`, режимы `native` (датаграммы) и `quic` (поток) [38].
- **libwebrtc** [39]:
  - `kVideoMtu` = 1200;
  - dcSCTP `kMaxSafeMTUSize` = 1191, то есть 1280 - 40 - 8 - 24 (GCM) - 13 (DTLS) - 4 (TURN).
- **Valve GameNetworkingSockets**: `MTU_PacketSize` = 1300, допустимо 200-1300 [40]. Часто пишут "1200", но в коде 1300.
- **DNS Flag Day 2020**: EDNS-буфер 1232 = 1280 - 48, при TC=1 запрос повторяется по TCP [41].

## 6. Контейнеры и виртуализация

- **Docker** [42]:
  - у сети по умолчанию MTU задается через `dockerd --mtu` или `"mtu"` в `daemon.json`;
  - пользовательская сеть этот MTU не наследует, ей нужна опция драйвера;
  - внутри VPN или оверлея мост с 1500 дает черную дыру. Примеры - в разделе 8 [`mtu.md`](mtu.md#8-инциденты-и-симптомы).

  ```bash
  docker network create -o com.docker.network.driver.mtu=1400 net1
  docker exec c1 ip link show eth0
  ```

- **Calico** определяет MTU автоматически [43]. Накладные: IPIP 20, VXLAN 50 для IPv4 и 70 для IPv6, WireGuard 60 и 80.
- **OpenStack Neutron** [44]:
  - базовое значение - `global_physnet_mtu`;
  - VXLAN стоит 50 байт, при IPv6-концах еще 20;
  - MTU раздается по DHCP (option 26) и через RA.
- **libvirt**: `<mtu size='1500'/>` с версии 3.1.0. При `VIRTIO_NET_F_MTU` гостевая ОС берет MTU из устройства [45].
- **Вывод**: у облачного VPS MTU может оказаться 1450 или 1460. Проверять `ip link` в гостевой ОС и `ping -M probe` наружу.

## 7. Методика: клиент - роутер - провайдер - сервер

1. **Локальные MTU на каждом узле.** На клиенте, роутере и сервере:

   ```bash
   ip -d link show; ip route get <peer>; ip route show cache
   ```

   Клиент за PPPoE почти наверняка на 1492, облачный VPS - на 1450-1500.
2. **PMTU в обе стороны.** С клиента на сервер и с сервера на клиента: пути бывают асимметричными. `ping -M probe -s N` с перебором N, затем `tracepath -n`. То же для IPv6 с `-6`.
3. **Настоящий предел или потеря ICMP.** На отправителе во время пробы запущен tcpdump с фильтрами Frag Needed и PTB (раздел 3).

   | Что видно | Вывод |
   | --- | --- |
   | пришел ICMP с `mtu = N`, `ip route get` показывает `cache ... mtu N` | настоящий предел N, PMTUD работает |
   | проба с DF размера S пропадает без ICMP, проба S - 8 проходит | черная дыра: ICMP режется фильтром, ECMP или ограничением скорости |
   | пропадает без ICMP, на приемнике растет `RX dropped` | кадр больше MRU в L2 |
   | пропадают пакеты любого размера, но не все | потери не из-за MTU, см. [`path-degradation.md`](path-degradation.md) |
   | пропадает только после нескольких секунд или десятков КБ | похоже на DPI или полисинг, а не на MTU |

4. **Кеш PMTU.** После одного ICMP `-M do` отказывает локально еще 600 с. Для повтора нужен `-M probe` или `ip route flush cache`.
5. **MSS clamping.** Снять SYN на LAN- и WAN-стороне роутера. Если `mss` на WAN меньше, чем на LAN, роутер делает clamping. Проверить стоит и SYN-ACK от сервера.

   ```bash
   tcpdump -ni lan -v 'tcp[tcpflags] & tcp-syn != 0'
   tcpdump -ni wan -v 'tcp[tcpflags] & tcp-syn != 0'
   ```

6. **TCP в черной дыре.** Смотреть `sysctl net.ipv4.tcp_mtu_probing` (значение 1 - безопасный вариант, так советует Cloudflare), счетчики `TCPMTUP*` и `ss -tin` (поля `pmtu` и `mss`). [лаб] Выгрузка 2 МБ через роутер, который глотает Frag Needed:

   | `tcp_mtu_probing` | Результат |
   | --- | --- |
   | 0 | не завершилась за 40 с (лимит стенда), 7 повторов |
   | 1 | 12,2 с |
   | 2 | 0,01 с |

   RTT в стенде почти нулевой. На реальном пути пауза зависит от RTO и числа повторов до `tcp_retries1`.
7. **UDP.**
   - Сравнить свой размер датаграммы с найденным PMTU. Для native UDP S5Core это 1428 по IPv4 и 1448 по IPv6.
   - Молчаливую фрагментацию видно по `IpFragCreates` у отправителя и `IpReasm*` у получателя, отказы IPv6 - по `Icmp6InPktTooBigs`.
   - Проверка: `iperf3 -u -l 1400 --dont-fragment`.
8. **Вложенные туннели.** Если клиент работает внутри другого VPN, вычитаются все обертки по очереди. Смотреть `ip route get <endpoint>`, как это делает wg-quick.

### Стенд без root

Узкое звено 1400 и черная дыра воспроизводятся в пользовательском пространстве имен без прав root. Этим стендом получены пункты [лаб]. Запуск - `unshare -Urnm bash stand.sh`:

```bash
set -e
mount -t tmpfs none /run; mkdir -p /run/netns
ip netns add A; ip netns add R; ip netns add B
ip link add a0 netns A type veth peer name r0 netns R
ip link add r1 netns R type veth peer name b0 netns B
ip -n A addr add 10.1.0.2/24 dev a0; ip -n R addr add 10.1.0.1/24 dev r0
ip -n R addr add 10.2.0.1/24 dev r1; ip -n B addr add 10.2.0.2/24 dev b0
for n in A R B; do ip -n $n link set lo up; done
ip -n A link set a0 up; ip -n R link set r0 up
ip -n R link set r1 up mtu 1400; ip -n B link set b0 up mtu 1400
ip -n A route add default via 10.1.0.1; ip -n B route add default via 10.2.0.1
ip netns exec R sysctl -qw net.ipv4.ip_forward=1
ip netns exec A ping -n -c1 -W1 -M do -s 1472 10.2.0.2 || true   # Frag needed (mtu = 1400)
ip netns exec A ip route get 10.2.0.2                          # cache expires 599sec mtu 1400
# черная дыра: роутер не отправляет Frag Needed
ip netns exec R nft add table ip f
ip netns exec R nft add chain ip f out '{ type filter hook output priority 0; }'
ip netns exec R nft add rule ip f out icmp type destination-unreachable icmp code frag-needed drop
```

Для TCP на veth нужно выключить offload (`ethtool -K <dev> tso off gso off gro off`), иначе ядро шлет сегменты больше MTU и собирает их на приеме.

## 8. Противоречия в документации

- **udp(7)** пишет, что Linux возвращает `EMSGSIZE`, когда запись больше PMTU. Код (`WANT`) и опыт показывают другое: ядро фрагментирует локально, а `EMSGSIZE` бывает только при `DO`, `PROBE` и `INTERFACE` или асинхронно после ICMP на подключенном сокете [лаб].
- **ip-route(8)** пишет, что с 3.6 `ip route show cached` ничего не выводит. Это устарело: вывод исключений вернули в 5.3, и на ядре 7.0 команда работает [46][лаб].
- **`UDP_MAX_SEGMENTS`**: udp(7) называет 64, в текущем `include/linux/udp.h` - 128.
- **Valve**: часто пишут 1200, в коде 1300 [40].
- **OpenVPN сменил смысл `mssfix`**. С 2.6 по умолчанию стоит `1492 mtu`, то есть полный внешний IP-пакет вместе с заголовками IP и UDP. До 2.6 по умолчанию было 1450 без внешних заголовков. Руководства, написанные до 2.6, описывают старое поведение [47].

## 9. Не подтверждено

- Учитывает ли современная Windows `EnablePMTUBHDetect` и как ведут себя ее VPN-адаптеры.
- Официальная онлайн-страница `networksetup -setMTU` (есть только локальный man).
- Типичные размеры игровых пакетов 100-500 байт.
- Работоспособность icmpcheck.popcount.org.

## Источники

1. Linux, net/ipv4/route.c: https://github.com/torvalds/linux/blob/master/net/ipv4/route.c
2. Linux, net/ipv6/route.c: https://github.com/torvalds/linux/blob/master/net/ipv6/route.c
3. ip-route(8): https://man7.org/linux/man-pages/man8/ip-route.8.html
4. Linux, ip-sysctl: https://docs.kernel.org/networking/ip-sysctl.html ; tcp.h: https://github.com/torvalds/linux/blob/master/include/net/tcp.h ; tcp_timer.c: https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_timer.c
5. IP_MTU_DISCOVER(2const): https://man7.org/linux/man-pages/man2/IP_MTU_DISCOVER.2const.html ; af_inet.c: https://github.com/torvalds/linux/blob/master/net/ipv4/af_inet.c ; in.h, in6.h: https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
6. IP_MTU(2const): https://man7.org/linux/man-pages/man2/IP_MTU.2const.html
7. IP_RECVERR(2const): https://man7.org/linux/man-pages/man2/IP_RECVERR.2const.html ; udp.c: https://github.com/torvalds/linux/blob/master/net/ipv4/udp.c
8. udp(7): https://man7.org/linux/man-pages/man7/udp.7.html
9. if_link.h: https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_link.h ; https://docs.kernel.org/networking/statistics.html
10. ping(8): https://man7.org/linux/man-pages/man8/ping.8.html
11. Windows ping: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ping
12. FreeBSD ping(8): https://man.freebsd.org/cgi/man.cgi?query=ping&sektion=8
13. tracepath(8): https://man7.org/linux/man-pages/man8/tracepath.8.html ; iputils: https://github.com/iputils/iputils
14. traceroute(8), пакет traceroute: https://man7.org/linux/man-pages/man8/traceroute.8.html
15. mtr(8): https://github.com/traviscross/mtr/blob/master/man/mtr.8.in
16. nmap path-mtu: https://nmap.org/nsedoc/scripts/path-mtu.html
17. scamper: https://www.caida.org/catalog/software/scamper/man/scamper.1.pdf
18. iperf3(1): https://github.com/esnet/iperf/blob/master/src/iperf3.1
19. pcap-filter(7): https://www.tcpdump.org/manpages/pcap-filter.7.html ; Wireshark: https://www.wireshark.org/docs/dfref/
20. test-ipv6.com, PMTUD: https://test-ipv6.com/faq_pmtud.html
21. RIPE Atlas tools: https://ripe-atlas-tools.readthedocs.io/en/latest/use.html
22. Windows Server 2003, TCP/IP registry: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc739819(v=ws.10) ; Windows 2000: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc960465(v=technet.10)
23. Microsoft, Advances in Windows Vista TCP/IP: https://learn.microsoft.com/en-us/archive/blogs/wndp/advances-in-windows-vista-tcpip ; Set-NetIPInterface: https://learn.microsoft.com/en-us/powershell/module/nettcpip/set-netipinterface
24. quic-go: https://github.com/quic-go/quic-go ; sys_conn_df_linux.go: https://github.com/quic-go/quic-go/blob/master/sys_conn_df_linux.go
25. XNU, tcp_timer.c: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp_timer.c
26. Apple Support, MTU: https://support.apple.com/guide/mac-help/mchlp2505/mac
27. FreeBSD tcp(4): https://man.freebsd.org/cgi/man.cgi?query=tcp&sektion=4
28. Android VpnService.Builder: https://developer.android.com/reference/android/net/VpnService.Builder
29. AOSP telephony, e970171: https://android.googlesource.com/platform/frameworks/opt/telephony/+/e970171%5E!/
30. OpenWrt, firewall и network: https://openwrt.org/docs/guide-user/firewall/firewall_configuration , https://openwrt.org/docs/guide-user/network/network_configuration
31. nftables, mangling packet headers: https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers
32. iptables-extensions, TCPMSS: https://ipset.netfilter.org/iptables-extensions.man.html
33. MikroTik, Mangle и PPP AAA: https://help.mikrotik.com/docs/spaces/ROS/pages/48660587/Mangle , https://help.mikrotik.com/docs/spaces/ROS/pages/132350049/PPP+AAA
34. Keenetic, MTU: https://support.keenetic.com/titan/kn-1811/en/19727.html
35. wg-quick: https://git.zx2c4.com/wireguard-tools/plain/src/wg-quick/linux.bash
36. Go, net/sockopt_linux.go: https://github.com/golang/go/blob/master/src/net/sockopt_linux.go
37. Hysteria 2: https://v2.hysteria.network/docs/advanced/Full-Server-Config/ , https://github.com/apernet/hysteria
38. TUIC v5: https://github.com/EAimTY/tuic/blob/dev/SPEC.md
39. libwebrtc, dcsctp_options.h: https://webrtc.googlesource.com/src/+/refs/heads/main/net/dcsctp/public/dcsctp_options.h
40. Valve GameNetworkingSockets: https://github.com/ValveSoftware/GameNetworkingSockets
41. DNS Flag Day 2020: https://www.dnsflagday.net/2020/
42. Docker, bridge driver: https://docs.docker.com/engine/network/drivers/bridge/
43. Calico, MTU: https://docs.tigera.io/calico/latest/networking/configuring/mtu
44. OpenStack Neutron, MTU: https://docs.openstack.org/neutron/latest/admin/config-mtu.html
45. libvirt, domain XML: https://libvirt.org/formatdomain.html
46. Патч возврата вывода исключений, 2019: https://patchwork.ozlabs.org/project/netdev/patch/8d3b68cd37fb5fddc470904cdd6793fcf480c6c1.1561131177.git.sbrivio@redhat.com/
47. OpenVPN, link-options: https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/link-options.rst
