#!/usr/bin/env python3
"""Что уходит мимо туннеля: матрица протокол x порт со сверкой адресов.

Заменяет прежнюю пробу по одному только STUN. Причина замены в замере
20.09.2026: утечку давали не STUN-серверы как таковые, а порты, которых не
было в списке перехвата. Один сервис проверки читал настоящий адрес через
WebTransport, то есть по HTTP/3 на UDP:4433, другой - обычным HTTPS на
TCP:8443. Проба, которая смотрит только на 3478 и 19302, оба случая
показывает чистыми.

Поэтому проверяются четыре оси сразу:

  порт        стандартный против произвольного (пара sipgate 3478/10000 -
              один и тот же сервер, так что разница в ответах говорит именно
              о номере порта)
  протокол    UDP против TCP: перехват UDP и TCP на роутере настраивается
              разными правилами и ломается независимо
  география   сервер в RU против сервера вне RU: правило вида GEOIP,RU,DIRECT
              отдает российскому серверу прямой путь
  версия IP   IPv6 мимо туннеля - это утечка в чистом виде, туннель его не
              несет

Запускать с той машины, чей адрес проверяется, а не с роутера: у роутера
свой путь наружу и он перехват не проходит.

  scripts/leak_matrix.py
  scripts/leak_matrix.py --node 203.0.113.10 --node 203.0.113.20
  scripts/leak_matrix.py --collector node.example:8443   # свой cmd/fpcollect

--node задает адреса выходных узлов. Без него проба только группирует
ответы: разные адреса могут быть и утечкой, и двумя узлами (TCP через один,
UDP через другой - это штатная настройка, если она сделана намеренно).
С ним вердикт становится однозначным: адрес вне списка - это утечка.
"""

import argparse
import json
import os
import socket
import ssl
import struct
import sys
import urllib.request

MAGIC = 0x2112A442

# (хост, порт, чем интересен) - UDP, STUN Binding Request.
STUN_TARGETS = [
    ("stun.l.google.com", 19302, "порт обычно перехватывают, сервер вне RU"),
    ("stun.cloudflare.com", 3478, "стандартный порт STUN, сервер вне RU"),
    ("stun.sipgate.net", 3478, "тот же сервер, стандартный порт"),
    ("stun.sipgate.net", 10000, "тот же сервер, порт произвольный"),
    ("stun.sipnet.ru", 3478, "стандартный порт, но сервер в RU"),
    ("stun.nextcloud.com", 443, "UDP:443 - его же занимает QUIC"),
]

# (url, чем интересен) - TCP, обычный HTTPS.
HTTPS_TARGETS = [
    ("https://api.ipify.org", "TCP:443, за Cloudflare"),
    ("https://checkip.amazonaws.com", "TCP:443, другой провайдер"),
]

IPV6_TARGETS = [
    ("https://api6.ipify.org", "IPv6 наружу"),
]


def stun_request():
    return struct.pack(">HHI", 0x0001, 0, MAGIC) + os.urandom(12)


def mapped_address(data):
    if len(data) < 20:
        return None
    mtype, mlen, _ = struct.unpack(">HHI", data[:8])
    if mtype != 0x0101:  # Binding Success Response
        return None
    pos, end = 20, min(20 + mlen, len(data))
    while pos + 4 <= end:
        atype, alen = struct.unpack(">HH", data[pos : pos + 4])
        val = data[pos + 4 : pos + 4 + alen]
        if atype == 0x0020 and len(val) >= 8:  # XOR-MAPPED-ADDRESS
            ip = bytes(a ^ b for a, b in zip(val[4:8], struct.pack(">I", MAGIC)))
            return socket.inet_ntoa(ip)
        if atype == 0x0001 and len(val) >= 8:  # MAPPED-ADDRESS
            return socket.inet_ntoa(val[4:8])
        pos += 4 + alen + ((4 - alen % 4) % 4)
    return None


def probe_stun(host, port, timeout=3.0):
    try:
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except OSError as err:
        return None, f"имя не разрешилось: {err}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(stun_request(), addr)
        got = mapped_address(sock.recvfrom(2048)[0])
        return (got, None) if got else (None, "ответ без адреса")
    except socket.timeout:
        return None, "нет ответа"
    except OSError as err:
        return None, f"ошибка {err}"
    finally:
        sock.close()


def probe_https(url, timeout=8.0):
    # Семейство адресов задается доменом, а не флагом сокета: api6.ipify.org
    # существует только в IPv6, поэтому запрос к нему проверяет именно IPv6,
    # а не то, что удалось выбрать резолверу.
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - адреса заданы в файле
            return resp.read().decode().strip().split("\n")[0], None
    except Exception as err:  # noqa: BLE001 - любая причина одинаково значит "не дошли"
        return None, f"{type(err).__name__}: {err}"


def probe_collector(hostport, timeout=8.0):
    """Свой cmd/fpcollect: отдает и адрес, и отпечаток TLS одним ответом."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # коллектор обычно с самоподписанным
    try:
        with urllib.request.urlopen(f"https://{hostport}/", timeout=timeout, context=ctx) as resp:  # noqa: S310
            return json.loads(resp.read()), None
    except Exception as err:  # noqa: BLE001
        return None, f"{type(err).__name__}: {err}"


def main():
    ap = argparse.ArgumentParser(description="матрица утечки мимо туннеля")
    ap.add_argument("--node", action="append", default=[], metavar="IP",
                    help="адрес выходного узла; можно повторять")
    ap.add_argument("--collector", metavar="HOST:PORT",
                    help="свой cmd/fpcollect - проверяет и адрес, и отпечаток TLS")
    args = ap.parse_args()

    rows = []
    print(f"{'протокол':9s} {'цель':30s} {'порт':>6s}  {'нас видят как':17s} чем интересен")

    for host, port, why in STUN_TARGETS:
        got, err = probe_stun(host, port)
        rows.append(("UDP", got))
        print(f"{'UDP':9s} {host:30s} {port:6d}  {(got or err or '-'):17s} {why}")

    for url, why in HTTPS_TARGETS:
        got, err = probe_https(url)
        rows.append(("TCP", got))
        host = url.split("//", 1)[1]
        print(f"{'TCP':9s} {host:30s} {443:6d}  {(got or err or '-'):17s} {why}")

    if args.collector:
        rep, err = probe_collector(args.collector)
        host, _, port = args.collector.partition(":")
        if rep:
            rows.append(("TCP", rep.get("ip")))
            print(f"{'TCP':9s} {host:30s} {port:>6s}  {rep.get('ip', '-'):17s} свой коллектор, порт произвольный")
            print(f"{'':9s} {'':30s} {'':6s}  отпечаток: ja4={rep.get('ja4')} alpn={rep.get('alpn_offered')} -> {rep.get('alpn_negotiated')!r}")
            if rep.get("note"):
                print(f"{'':9s} {'':30s} {'':6s}  {rep['note']}")
        else:
            print(f"{'TCP':9s} {host:30s} {port:>6s}  {'-':17s} коллектор не ответил: {err}")

    for url, why in IPV6_TARGETS:
        got, err = probe_https(url)
        host = url.split("//", 1)[1]
        shown = got or "наружу не ходит"
        print(f"{'IPv6':9s} {host:30s} {443:6d}  {shown:17s} {why}")
        if got:
            rows.append(("IPv6", got))

    seen = {}
    for proto, ip in rows:
        if ip:
            seen.setdefault(ip, set()).add(proto)

    print()
    if not seen:
        print("Ни один источник не ответил - проверять нечего, разберитесь со связью.")
        return 2

    nodes = set(args.node)
    if nodes:
        strangers = {ip: p for ip, p in seen.items() if ip not in nodes}
        if strangers:
            print("Адреса вне списка узлов - это трафик мимо туннеля:")
            for ip, protos in sorted(strangers.items()):
                print(f"  {ip:17s} по {', '.join(sorted(protos))}")
            return 1
        print(f"Все ответы пришли с заявленных узлов ({', '.join(sorted(nodes))}) - утечки по этим осям нет.")
        return 0

    if len(seen) > 1:
        print("Адресов больше одного:")
        for ip, protos in sorted(seen.items()):
            print(f"  {ip:17s} по {', '.join(sorted(protos))}")
        print()
        print("Это либо утечка, либо разные выходные узлы на разные протоколы.")
        print("Чтобы получить однозначный вердикт, назовите узлы: --node IP [--node IP]")
        return 1

    print(f"Все источники видят один адрес ({next(iter(seen))}) - утечки по этим осям нет.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
