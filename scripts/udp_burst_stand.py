#!/usr/bin/env python3
"""Стенд всплеска ответов UDP (Ч-2 в docs/plan/draft.md, К-6 в docs/plan/v2.3-rc3.md).

Игровой сервер отвечает всплесками: на узле, где матч терял 5% входящих,
всплеск приходил волной около 450 датаграмм по 928 байт за 5-10 мс, затем
хвостом около 2000 в секунду. Сокет по пути, который держит меньше волны,
теряет остаток, как бы быстро его ни читали. Стенд поднимает s5core, s5client
и источник всплесков (`udpprobe -echo`) в своем сетевом пространстве
(`unshare -Urn`, root не нужен) и считает, сколько датаграмм дошло до
приложения и какой сокет отбросил остальные.

    ./scripts/udp_burst_stand.py --server bin/s5core --client bin/s5client --label rc3
    ./scripts/udp_burst_stand.py --server ... --client ... --pin 3 --hog --path tcp
    ./scripts/udp_burst_stand.py --path direct --label control

Путь `direct` - контроль: те же всплески прямо в приложение, без сервера и
клиента.

Без root стенд живет в user namespace, где ни у одного процесса нет
CAP_NET_ADMIN исходного пространства: и сервер, и приложение получают буфер
под потолком net.core.rmem_max хоста. Под root стенд создает только сетевое
пространство, а `--server-user` запускает s5core под этим uid без
capabilities, как в контейнере: источник и приложение остаются под root и
держат всплеск целиком, поэтому все отбросы принадлежат серверу и клиенту.

`--cut-native N` через N секунд после начала отбрасывает датаграммы сервера
к клиенту по native (nftables в том же пространстве): клиент перестает
слышать сервер, и ответы до конца прогона идут по TCP управляющего
соединения, через его очередь кадров.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_tcp(port, t=10):
    end = time.time() + t
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


def rcvbuf_errors():
    total = 0
    lines = open("/proc/net/snmp").read().splitlines()
    for names, values in zip(lines, lines[1:]):
        if names.startswith("Udp: ") and values.startswith("Udp: "):
            total += int(values.split()[names.split().index("RcvbufErrors")])
            break
    try:
        for line in open("/proc/net/snmp6"):
            if line.startswith("Udp6RcvbufErrors"):
                total += int(line.split()[1])
    except OSError:
        pass
    return total


def backlog_drops():
    # Второй столбец softnet_stat - пакеты, отброшенные на полной очереди
    # приема CPU (netdev_max_backlog); счетчик общий для хоста.
    try:
        return sum(int(line.split()[1], 16) for line in open("/proc/net/softnet_stat"))
    except (OSError, IndexError, ValueError):
        return None


def metrics(port):
    try:
        body = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            f"http://127.0.0.1:{port}/metrics", timeout=3).read().decode()
    except OSError as e:
        return {"error": str(e)}
    out = {}
    for line in body.splitlines():
        if line.startswith(("s5core_native_udp_datagrams_total", "s5core_native_udp_route_events_total",
                            "s5core_native_udp_stream_drops_total", "s5core_udp_receive_buffer_drops_total")):
            name, val = line.rsplit(" ", 1)
            name = re.sub(r'otel_scope_\w+="[^"]*",?', "", name).replace(",}", "}").replace("{}", "")
            out[name] = float(val)
    return out


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest() if path else None


def start(cmd, env, log, pin=None, user=None):
    if user is not None:
        cmd = ["setpriv", f"--reuid={user}", f"--regid={user}", "--clear-groups"] + cmd
    if pin is not None:
        cmd = ["taskset", "-c", str(pin)] + cmd
    return subprocess.Popen(cmd, env=dict(env, PATH=os.environ["PATH"]), stdout=log, stderr=log)


def stop(*procs):
    for p in procs:
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()


def cut_native(port):
    # На входе, а не на выходе: отброс на выходе вернул бы серверу EPERM, и
    # ответ ушел бы по TCP раньше, чем клиент заметит потерю, как в сети.
    for cmd in (["add", "table", "inet", "stand"],
                ["add", "chain", "inet", "stand", "in", "{ type filter hook input priority 0; }"],
                ["add", "rule", "inet", "stand", "in", "udp", "sport", str(port), "drop"]):
        subprocess.run(["nft"] + cmd, check=True)


def run(a):
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    psk = os.urandom(16).hex()
    obfs, plain, mport, cport = free_port(), free_port(), free_port(), free_port()
    origin = free_port(socket.SOCK_DGRAM)
    senv = dict(PROXY_LISTEN_IP="127.0.0.1", PROXY_PORT=str(plain), OBFS_ENABLED="true",
                OBFS_PORT=str(obfs), OBFS_PSK=psk, UDP_PORT=str(obfs), METRICS_PORT=str(mport),
                METRICS_BIND_ADDR="127.0.0.1", REQUIRE_AUTH="false", LOG_LEVEL="info")
    cenv = dict(CLIENT_LISTEN_ADDR=f"127.0.0.1:{cport}", SERVER_ADDR=f"127.0.0.1:{obfs}",
                OBFS_PSK=psk, TRANSPORT="obfs", UDP_NATIVE="true" if a.path == "native" else "false",
                LOG_LEVEL="info")
    logs = {k: open(os.path.join(out, f"{a.label}-{k}.log"), "w") for k in ("server", "client", "origin")}
    procs = []
    hog = None
    try:
        procs.append(start([a.probe, "-echo", f"127.0.0.1:{origin}"], {}, logs["origin"]))
        socks = None
        if a.path != "direct":
            procs.append(start([a.server], senv, logs["server"], a.pin, a.server_user))
            if not wait_tcp(obfs):
                raise RuntimeError("server did not listen")
            socks = f"127.0.0.1:{plain}"
        if a.path in ("native", "tcp"):
            procs.append(start([a.client], cenv, logs["client"]))
            if not wait_tcp(cport):
                raise RuntimeError("client did not listen")
            socks = f"127.0.0.1:{cport}"
        if a.hog:
            hog = subprocess.Popen(["taskset", "-c", str(a.pin), sys.executable, "-c", "while True: pass"])
        time.sleep(0.5)
        before, backlog_before = rcvbuf_errors(), backlog_drops()
        cut = threading.Timer(a.cut_native, cut_native, (obfs,)) if a.cut_native is not None else None
        if cut:
            cut.start()
        report = os.path.join(out, f"{a.label}.probe.json")
        probe = subprocess.run([a.probe, "-target", f"127.0.0.1:{origin}"] + (["-socks", socks] if socks else []) +
                               ["-bursts", str(a.bursts), "-burst-size", str(a.size), "-wave", str(a.wave),
                                "-wave-for", a.wave_for, "-tail", str(a.tail), "-tail-every", a.tail_every,
                                "-gap", a.gap, "-label", a.label, "-json", report],
                               capture_output=True, text=True, timeout=a.bursts * 10 + 60)
        after, backlog_after = rcvbuf_errors(), backlog_drops()
        if cut:
            cut.cancel()
        sys.stdout.write(probe.stdout)
        if probe.returncode != 0:
            raise RuntimeError(f"probe failed: {probe.stderr.strip()}")
        m = metrics(mport) if socks else {}
    finally:
        stop(hog, *reversed(procs))
        for f in logs.values():
            f.close()
    rep = json.load(open(report))
    server_log = open(os.path.join(out, f"{a.label}-server.log")).read().splitlines()
    result = {
        "label": a.label, "path": a.path, "pin": a.pin, "hog": a.hog, "cut_native": a.cut_native,
        "root": os.geteuid() == 0 and os.environ.get("UDP_BURST_STAND_NS") == "root", "server_user": a.server_user,
        "server_sha256": sha256(a.server), "client_sha256": sha256(a.client),
        "rmem_max": int(open("/proc/sys/net/core/rmem_max").read()),
        "rmem_default": int(open("/proc/sys/net/core/rmem_default").read()),
        "sent": rep["sent"], "lost": rep["lost"],
        "loss_pct": round(100 * rep["lost"] / max(1, rep["sent"]), 3),
        "per_burst_lost": [b["lost"] for b in rep["bursts"]],
        "rcvbuf_errors": after - before,
        "backlog_drops": None if backlog_before is None or backlog_after is None else backlog_after - backlog_before,
        "socket_drops": [s for s in rep.get("sockets", []) if s["drops"]],
        "server_buffer_log": [l for l in server_log if "UDP receive buffer" in l],
        "metrics": m,
    }
    json.dump(result, open(os.path.join(out, f"{a.label}.json"), "w"), indent=1)
    print(f"{a.label}: netns RcvbufErrors +{result['rcvbuf_errors']}, backlog drops +{result['backlog_drops']}, "
          f"socket drops {[(s['owner'], s['drops']) for s in result['socket_drops']]}")
    for line in result["server_buffer_log"]:
        print(f"{a.label}: {line}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--server")
    p.add_argument("--client")
    p.add_argument("--probe", default=os.path.join(ROOT, "bin", "udpprobe"))
    p.add_argument("--label", required=True)
    p.add_argument("--out", default=os.path.join(ROOT, "bench", "burst"))
    p.add_argument("--path", choices=("native", "tcp", "plain", "direct"), default="native",
                   help="native: 0x84 через s5client, tcp: 0x83 через s5client, plain: 0x03 прямо в s5core, "
                        "direct: без прокси")
    p.add_argument("--bursts", type=int, default=20)
    p.add_argument("--size", type=int, default=928)
    p.add_argument("--wave", type=int, default=450)
    p.add_argument("--wave-for", default="5ms")
    p.add_argument("--tail", type=int, default=450)
    p.add_argument("--tail-every", default="500us")
    p.add_argument("--gap", default="2s")
    p.add_argument("--pin", type=int, help="CPU, к которому привязан s5core")
    p.add_argument("--hog", action="store_true", help="занять тот же CPU циклом, нужен --pin")
    p.add_argument("--server-user", type=int, help="uid, под которым идет s5core без capabilities, только под root")
    p.add_argument("--cut-native", type=float, metavar="N",
                   help="через N с отбросить native-датаграммы сервера к клиенту, только для --path native")
    a = p.parse_args()
    if a.hog and a.pin is None:
        p.error("--hog needs --pin")
    if a.path != "direct" and not a.server or a.path in ("native", "tcp") and not a.client:
        p.error(f"--path {a.path} needs --server" + (" and --client" if a.path in ("native", "tcp") else ""))
    if a.cut_native is not None and a.path != "native":
        p.error("--cut-native needs --path native")
    if a.path == "direct":
        a.server = a.client = None
    root = os.geteuid() == 0
    if a.server_user is not None and not root:
        p.error("--server-user needs root")
    if "UDP_BURST_STAND_NS" not in os.environ:
        env = dict(os.environ, UDP_BURST_STAND_NS="root" if root else "user")
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            env.pop(k, None)
        sys.exit(subprocess.call(["unshare", "-n" if root else "-Urn", sys.executable] + sys.argv, env=env))
    run(a)


if __name__ == "__main__":
    main()
