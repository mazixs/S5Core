#!/usr/bin/env python3
"""Markdown report from the S5Core session journal (SESSION_LOG_FILE).

  journal_report.py sessions.jsonl [sessions-20260930T101500.000Z.jsonl.gz ...]
                    [--client-log s5client.log] [--service-log s5core.log] [--slow-dial-ms 800] [--long-s 1800]

Reads the files it is given, rotated .gz included, and never touches the network. The fields are the closed
set of pkg/s5server/journal.go: a line with others, or with no JSON at all, is counted at the end of the report
and does not stop it. The journal holds no client address and no key, and the report adds none; the client log
is read for the conn id, the close reason, the time and the duration only, and the service log for its
silent_burst lines only.
"""

import argparse
import bisect
import gzip
import heapq
import json
import math
import os
import re
import statistics
import sys
import zlib
from collections import Counter, defaultdict, namedtuple
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
MSK = timezone(timedelta(hours=3))

# journalFields of pkg/s5server/journal_test.go; the test of this script compares the two. The script tests run by
# hand (python3 -m unittest discover -s scripts/tests); scripts/pre-commit.sh does not run them.
KNOWN_FIELDS = frozenset("""
time level msg event seq boot version go_version pid transports session_log prev_unclean uptime_s conns open
reload failed dropped conn account auth transport client cmd dst_net dst_port dst_kind result stage end
server_timeouts resets dial_ms dial_tries dial_backups dial_backup_won first_byte_ms dur_ms up down dgram_up
dgram_down rotations answered native_up native_down path_moves tunnel_drops assocs rcvbuf_drops tcp_rtt_ms
tcp_unacked tcp_retransmits tcp_since_data_ms tcp_since_ack_ms
""".split())

SESSION_EVENTS = ("conn_end", "assoc_end")
PROCESS_EVENTS = ("process_start", "process_stop", "config_reload", "log_gap")
NOTE_EVENTS = ("silent_burst", "udp_rcvbuf_drops")
# What the minute counters count: server_timeouts is end=server_timeout, resets is end=reset.
CLUSTER_ENDS = ("server_timeout", "reset")
NUMERIC_FIELDS = frozenset("""
seq pid uptime_s conns open reload dropped dst_port server_timeouts resets dial_ms dial_tries dial_backups
first_byte_ms dur_ms up down dgram_up dgram_down rotations native_up native_down path_moves tunnel_drops assocs
rcvbuf_drops tcp_rtt_ms tcp_unacked tcp_retransmits tcp_since_data_ms tcp_since_ack_ms
""".split())
TCP_FIELDS = (("tcp_rtt_ms", "rtt, мс"), ("tcp_unacked", "unacked"), ("tcp_retransmits", "retransmits"),
              ("tcp_since_data_ms", "since_data, мс"), ("tcp_since_ack_ms", "since_ack, мс"))
TCP_LABEL = dict(TCP_FIELDS)
# The ends that carry tcp_* and the fields shown for each. tcp_unacked is judged on server_timeout only: a reset may
# come from the target, an association timeout from a deadline on a live socket, and after the kernel's own ETIMEDOUT
# the send queue is already empty, so there it says nothing about the path.
TCP_VIEWS = (
    ("server_timeout", "server_timeout (conn_end)", tuple(k for k, _ in TCP_FIELDS)),
    ("reset", "reset (conn_end, assoc_end)", ("tcp_retransmits", "tcp_since_ack_ms")),
    ("timeout", "timeout (assoc_end)", ("tcp_retransmits", "tcp_since_ack_ms")),
)
SILENT_ENDS = frozenset(end for end, _, _ in TCP_VIEWS)
NONE = "(нет)"
# Below this many datagrams the share carried natively says nothing: an association starts on the stream.
MIN_DGRAMS = 20
# The drops line comes first in the slice that writes it, the account lines of that slice right after it.
LINK_WINDOW = 0.5
NO_PORT = -1


def is_number(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and not math.isfinite(v):
        return False
    return abs(v) <= 1 << 63


def num(d, key, default=0):
    v = d.get(key)
    return v if is_number(v) else default


def check_numbers(d, bad, fields=NUMERIC_FIELDS):
    """Counts the numeric fields that hold something else; num() reads them as absent."""
    for k in fields & d.keys():
        if not is_number(d[k]):
            bad[k] += 1


def text(d, key):
    v = d.get(key)
    return v if isinstance(v, str) else ""


STAMP = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d", re.ASCII)


def parse_time(s):
    """RFC 3339 as the journal and slog write it; Python before 3.11 does not read the Z."""
    if not isinstance(s, str) or not STAMP.fullmatch(s[:19]):
        return None
    try:
        t = datetime(int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]), int(s[14:16]), int(s[17:19]),
                     tzinfo=UTC)
        rest = s[19:]
        if rest.startswith("."):
            digits = re.match(r"\d*", rest[1:], re.ASCII).group()
            if not digits:
                return None
            t = t.replace(microsecond=int(digits[:6].ljust(6, "0")))
            rest = rest[1 + len(digits):]
        if rest not in ("", "Z"):
            sign = {"+": 1, "-": -1}.get(rest[0])
            zone = rest[1:].replace(":", "")
            if sign is None or len(zone) != 4 or not zone.isdigit():
                return None
            t -= sign * timedelta(hours=int(zone[:2]), minutes=int(zone[2:]))
    except (ValueError, OverflowError):
        return None
    return t if 1970 <= t.year <= 2200 else None


def floor_hour(t):
    return t.replace(minute=0, second=0, microsecond=0)


def floor_minute(t):
    return t.replace(second=0, microsecond=0)


def fmt_t(t, secs=False):
    if t is None:
        return "-"
    fmt = "%Y-%m-%d %H:%M:%S" if secs else "%Y-%m-%d %H:%M"
    m = t.astimezone(MSK)
    msk = m.strftime(("%H:%M:%S" if secs else "%H:%M") if m.date() == t.date() else fmt)
    return f"{t.strftime(fmt)} UTC / {msk} МСК"


def human(n):
    n = float(n)
    if abs(n) < 1024:
        return f"{n:.0f} Б"
    for unit in ("КиБ", "МиБ", "ГиБ"):
        n /= 1024
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
    return f"{n / 1024:.1f} ТиБ"


def hms(ms):
    s = int(ms // 1000)
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}"


def fnum(x):
    if isinstance(x, float):
        x = round(x, 1)
        if x == int(x):
            x = int(x)
    return str(x)


def yes_no(v):
    return "да" if v is True else "нет" if v is False else "-"


def pct(part, whole):
    return f"{100 * part / whole:.1f}%" if whole else "-"


def percentile(sorted_values, p):
    return sorted_values[max(0, math.ceil(len(sorted_values) * p) - 1)]


def ranked(counter, n=None):
    """Most common first, equals by name: Counter.most_common keeps equals in the order of the first read."""
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def ends(counter):
    return " ".join(f"{k}={v}" for k, v in ranked(counter)) or "-"


def cell(v):
    s = str(v).replace("|", "\\|").replace("\n", " ")
    return s or "-"


def table(headers, rows, right=()):
    if not rows:
        return ["Нет данных.", ""]
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---:" if i in right else "---" for i in range(len(headers))) + " |"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return out + [""]


class FileInfo:
    def __init__(self, name):
        self.name = name
        self.lines = 0
        self.error = ""


def open_text(path):
    with open(path, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def read_lines(path, info):
    """Lines of a plain or gzip file; a file that breaks half way keeps what was read."""
    try:
        with open_text(path) as fh:
            yield from fh
    except (OSError, EOFError, zlib.error) as e:
        info.error = f"{type(e).__name__}: {e}"


def decode(raw, skipped):
    raw = raw.strip()
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except (ValueError, RecursionError):
        skipped["не JSON (в том числе оборванная строка)"] += 1
        return None
    if not isinstance(d, dict):
        skipped["JSON, но не объект"] += 1
        return None
    return d


Closed = namedtuple("Closed", "t closed_by dur_ms")
CLIENT_NUMBERS = frozenset(("dur_ms", "up", "down"))


class ClientLog:
    """The "TCP Tunnel closed" lines of s5client by conn; dest, server and error are not kept."""

    def __init__(self, paths):
        self.conns = {}
        self.files = []
        self.lines = 0
        self.tcp = 0
        self.skipped = Counter()
        self.bad = Counter()
        for path in paths:
            info = FileInfo(os.path.basename(path))
            self.files.append(info)
            for raw in read_lines(path, info):
                d = decode(raw, self.skipped)
                if d is None:
                    continue
                info.lines += 1
                self.lines += 1
                if d.get("msg") != "TCP Tunnel closed":
                    continue
                self.tcp += 1
                conn, t = text(d, "conn"), parse_time(d.get("time"))
                if not conn:
                    self.skipped["TCP Tunnel closed без conn"] += 1
                    continue
                if t is None:
                    self.skipped["TCP Tunnel closed без корректного time"] += 1
                    continue
                check_numbers(d, self.bad, CLIENT_NUMBERS)
                self.conns.setdefault(conn, Closed(t, text(d, "closed_by"), num(d, "dur_ms")))


class Top:
    """The n largest items by key; of equals the one with the earlier `when` wins, then the one read first.

    `when` is the time of the line: files come in any order, and the rotated ones are often listed newest first.
    The read count is unique, so the comparison of entries never reaches the item.
    """

    def __init__(self, n):
        self.n = max(n, 0)
        self.count = 0
        self.heap = []

    def add(self, key, item, when=0.0):
        self.count += 1
        if not self.n:
            return
        entry = (key, -when, -self.count, item)
        if len(self.heap) < self.n:
            heapq.heappush(self.heap, entry)
        elif entry > self.heap[0]:
            heapq.heapreplace(self.heap, entry)

    def items(self):
        return [e[3] for e in sorted(self.heap, reverse=True)]


class Bucket:
    __slots__ = ("conn", "assoc", "conn_end", "assoc_end", "up", "down", "minute_conns")

    def __init__(self):
        self.conn = self.assoc = self.up = self.down = self.minute_conns = 0
        self.conn_end = Counter()
        self.assoc_end = Counter()


EXPECTED, POSSIBLE, CONTRADICTION = "ожидаемо", "возможно", "противоречие"
VERDICTS = (EXPECTED, POSSIBLE, CONTRADICTION)
# relayClosedBy of s5client (the first direction to end) against ConnEnd.End() of the server. The key "*" is every
# end not named. The client writes app, tunnel_error and timeout only after a successful CONNECT reply, so a setup
# that failed on the server (SETUP_FAILED) cannot be one event with them; a refused CONNECT is logged with
# closed_by=server instead. The rest is a race, a lost FIN, an error of the application's own socket (app) or a
# dead path (timeout after TUNNEL_DEAD_TIMEOUT, which fits any end that happened on the server earlier). That
# includes client=server with end=client: each side sends its FIN before it decides which half ended first, so on
# a slow host both can see the other's close first.
SETUP_FAILED = ("rules_denied", "private_dest", "resolve_failed", "dial_timeout", "dial_refused", "dial_unreachable")
AGREEMENT = {
    "app": {"client": EXPECTED, **dict.fromkeys(SETUP_FAILED, CONTRADICTION), "*": POSSIBLE},
    "server": {"target": EXPECTED, "server_timeout": EXPECTED, "account": EXPECTED, "shutdown": EXPECTED,
               "reset": EXPECTED, **dict.fromkeys(SETUP_FAILED, EXPECTED), "*": POSSIBLE},
    "tunnel_error": {"reset": EXPECTED, "server_timeout": EXPECTED, "account": EXPECTED, "shutdown": EXPECTED,
                     **dict.fromkeys(SETUP_FAILED, CONTRADICTION), "*": POSSIBLE},
    "timeout": {"server_timeout": EXPECTED, "reset": EXPECTED, **dict.fromkeys(SETUP_FAILED, CONTRADICTION),
                "*": POSSIBLE},
}


def judge(client_by, end):
    rules = AGREEMENT.get(client_by)
    if rules is None:
        return POSSIBLE
    return rules.get(end, rules["*"])


def agreement_lines():
    lines = []
    for by, rules in AGREEMENT.items():
        named = ["{} - {}".format(v, ", ".join(e for e, x in rules.items() if x == v and e != "*"))
                 for v in VERDICTS if any(x == v and e != "*" for e, x in rules.items())]
        lines.append(f"- `{by}`: {'; '.join(named)}; прочие end - {rules['*']}.")
    return lines


def native_state(d, share_min):
    reasons = []
    if num(d, "path_moves") > 0:
        reasons.append("path_moves")
    if num(d, "tunnel_drops") > 0:
        reasons.append("tunnel_drops")
    total = num(d, "dgram_up") + num(d, "dgram_down")
    share = (num(d, "native_up") + num(d, "native_down")) / total if total else None
    if total >= MIN_DGRAMS and share < share_min:
        reasons.append("low_native")
    return reasons, share


class Journal:
    def __init__(self, opts, client=None):
        self.opts = opts
        self.client = client.conns if client else {}
        self.lines = 0
        self.skipped = Counter()
        self.bad = Counter()
        self.unknown = Counter()
        self.events = Counter()
        self.first = self.last = None
        self.by_hour = defaultdict(Bucket)
        self.by_account = defaultdict(Bucket)
        self.clients = Counter()
        self.transports = Counter()
        self.modes = Counter()
        self.proc = []
        self.gap_lost = 0
        self.min_conn = defaultdict(lambda: defaultdict(lambda: [0, 0]))
        self.min_acct = defaultdict(lambda: defaultdict(lambda: [0, 0]))
        self.silent = []
        self.notes = []
        self.assoc_minutes = []
        self.dial_n = 0
        self.dials = []
        self.dst = defaultdict(lambda: [0, 0, 0, 0])
        self.slow = Top(opts.top)
        self.dial_timeouts = Counter()
        self.backups = [0, 0, 0]
        self.long = Top(opts.top)
        self.long_ends = Counter()
        self.assoc_cmd = defaultdict(Counter)
        self.assoc_ends = defaultdict(Counter)
        self.native = Counter()
        self.flagged = Top(opts.top)
        self.matched = set()
        self.pairs = Counter()
        self.client_timeouts = Top(opts.top)

    def feed(self, raw):
        d = decode(raw, self.skipped)
        if d is None:
            return
        event = d.get("event")
        if not isinstance(event, str) or not event:
            self.skipped["нет поля event"] += 1
            return
        t = parse_time(d.get("time"))
        if t is None:
            self.skipped["нет корректного time"] += 1
            return
        self.lines += 1
        self.events[event] += 1
        if self.first is None or t < self.first:
            self.first = t
        if self.last is None or t > self.last:
            self.last = t
        for k in d.keys() - KNOWN_FIELDS:
            self.unknown[k] += 1
        check_numbers(d, self.bad)
        if event in SESSION_EVENTS:
            self.session(d, t, event)
        elif event == "account_minute":
            self.account_minute(d, t)
        elif event in PROCESS_EVENTS:
            self.proc.append((t, d, event))
            if event == "process_start":
                self.modes[text(d, "session_log") or NONE] += 1
            elif event == "log_gap":
                self.gap_lost += num(d, "dropped")
        elif event in NOTE_EVENTS:
            self.notes.append(dict(t=t, d=d, event=event, accounts=[]))

    def feed_service(self, raw, info):
        """From the service log only silent_burst, which the journal does not carry; every other line is not read."""
        if "silent_burst" not in raw:
            return
        skipped, bad = Counter(), Counter()
        d = decode(raw, skipped)
        if d is not None and d.get("event") == "silent_burst":
            t = parse_time(d.get("time"))
            if t is None:
                skipped["нет корректного time"] += 1
            else:
                check_numbers(d, bad)
                info.lines += 1
                self.notes.append(dict(t=t, d=d, event="silent_burst", accounts=[]))
        for total, local in ((self.skipped, skipped), (self.bad, bad)):
            for name, n in local.items():
                total["служебный лог: " + name] += n

    def account_minute(self, d, t):
        account = text(d, "account") or "-"
        self.by_hour[(floor_hour(t), account)].minute_conns += num(d, "conns")
        st, rs = num(d, "server_timeouts"), num(d, "resets")
        if st or rs:
            c = self.min_acct[floor_minute(t)][account]
            c[0] += st
            c[1] += rs
        if num(d, "assocs") > 0:
            self.assoc_minutes.append((t.timestamp(), account, num(d, "assocs"), num(d, "up"), num(d, "down")))

    def link_drops(self):
        """The drops line and the account lines of one slice are written together, the drops first; the files may
        come in any order."""
        self.assoc_minutes.sort()
        stamps = [m[0] for m in self.assoc_minutes]
        for rec in self.notes:
            if rec["event"] != "udp_rcvbuf_drops":
                continue
            at = rec["t"].timestamp()
            lo = bisect.bisect_left(stamps, at)
            hi = bisect.bisect_right(stamps, at + LINK_WINDOW)
            rec["accounts"] = [m[1:] for m in self.assoc_minutes[lo:hi]]

    def session(self, d, t, event):
        udp = event == "assoc_end"
        account = text(d, "account") or "-"
        # closed_by and reason are what older journals called the end.
        end = text(d, "end") or text(d, "closed_by") or text(d, "reason") or text(d, "result") or "?"
        up, down = num(d, "up"), num(d, "down")
        for b in (self.by_hour[(floor_hour(t), account)], self.by_account[account]):
            if udp:
                b.assoc += 1
                b.assoc_end[end] += 1
            else:
                b.conn += 1
                b.conn_end[end] += 1
            b.up += up
            b.down += down
        self.clients[text(d, "client") or NONE] += 1
        self.transports[text(d, "transport") or NONE] += 1
        minute = floor_minute(t)
        if end in CLUSTER_ENDS:
            self.min_conn[minute][account][0 if end == "server_timeout" else 1] += 1
        if end in SILENT_ENDS:
            self.silent.append((end, minute, tuple(num(d, k, None) for k, _ in TCP_FIELDS)))
        if udp:
            self.assoc(d, t, end)
            return
        self.dial(d, t, account, end)
        dur = num(d, "dur_ms")
        if dur >= self.opts.long_s * 1000:
            self.long_ends[end] += 1
            self.long.add(dur, (t, d, end), t.timestamp())
        self.join_client(d, t, account, end)

    def assoc(self, d, t, end):
        cmd = text(d, "cmd") or NONE
        c = self.assoc_cmd[cmd]
        c["n"] += 1
        c["dgram_up"] += num(d, "dgram_up")
        c["dgram_down"] += num(d, "dgram_down")
        c["up"] += num(d, "up")
        c["down"] += num(d, "down")
        if num(d, "rotations") > 0:
            c["rotated"] += 1
            c["answered"] += d.get("answered") is True
        self.assoc_ends[cmd][end] += 1
        if cmd != "native":
            return
        n = self.native
        n["n"] += 1
        n["up"] += num(d, "native_up")
        n["down"] += num(d, "native_down")
        n["dgrams"] += num(d, "dgram_up") + num(d, "dgram_down")
        n["moves"] += num(d, "path_moves")
        n["moved"] += num(d, "path_moves") > 0
        n["drops"] += num(d, "tunnel_drops")
        n["dropped"] += num(d, "tunnel_drops") > 0
        reasons, share = native_state(d, self.opts.native_share)
        if reasons:
            key = (num(d, "path_moves"), num(d, "tunnel_drops"), -1 if share is None else -share)
            self.flagged.add(key, (t, d, end, reasons, share), t.timestamp())

    def dial(self, d, t, account, end):
        timeout = end == "dial_timeout" or text(d, "result") == "dial_timeout"
        if num(d, "dial_tries") <= 0 and not timeout:
            return
        # dial_ms is written with dial_tries only: a dial_timeout without them has no time to measure.
        ms = num(d, "dial_ms", None)
        self.dial_n += 1
        if ms is not None:
            self.dials.append(ms)
        port = num(d, "dst_port", None)
        row = self.dst[(text(d, "dst_net") or "-", NO_PORT if port is None or port < 0 else int(port))]
        row[0] += 1
        if ms is not None and ms > self.opts.slow_dial_ms:
            row[1] += 1
            self.slow.add(ms, (t, d, end), t.timestamp())
        if timeout:
            row[2] += 1
            self.dial_timeouts[account] += 1
        backups = num(d, "dial_backups")
        if backups > 0:
            row[3] += 1
            self.backups[0] += 1
            self.backups[1] += backups
            self.backups[2] += d.get("dial_backup_won") is True

    def join_client(self, d, t, account, end):
        conn = text(d, "conn")
        c = self.client.get(conn)
        if c is None:
            return
        self.matched.add(conn)
        self.pairs[(c.closed_by or NONE, end)] += 1
        if c.closed_by == "timeout":
            self.client_timeouts.add((c.t.timestamp(), conn), (c.t, conn, account, end, num(d, "dur_ms"), c.dur_ms))


def clusters(src, min_accounts):
    rows, minutes = [], set()
    for minute in sorted(src):
        accts = {a: c for a, c in src[minute].items() if c[0] + c[1] > 0}
        if len(accts) < min_accounts:
            continue
        minutes.add(minute)
        per = "; ".join(f"{a}: st={c[0]} rs={c[1]}"
                        for a, c in sorted(accts.items(), key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0])))
        rows.append([fmt_t(minute), len(accts), sum(c[0] for c in accts.values()),
                     sum(c[1] for c in accts.values()), per])
    return rows, minutes


def by_accounts(rows, n):
    """Most accounts first, the earlier minute first among equals (the rows come in time order)."""
    return sorted(rows, key=lambda r: -r[1])[:n]


def section_summary(j, out):
    out += ["## 1. Сводка", ""]
    if not j.lines:
        out.extend(["Строк журнала нет.", ""])
        return
    out += [f"- Период: {fmt_t(j.first, True)} - {fmt_t(j.last, True)}",
            f"- Строк разобрано: {j.lines}"]
    if j.modes.get("abnormal"):
        out.append("- В журнале есть запуск с `session_log=abnormal`: `conn_end` записаны не для всех соединений, "
                   "доли и числа по строкам относятся к записанным, полные счета дает `account_minute`.")
    if j.gap_lost:
        out.append(f"- Строк потеряно писателем (`log_gap`): {j.gap_lost}.")
    out.append("")
    group = {"conn_end": "сессии", "assoc_end": "сессии", "account_minute": "минутные счетчики"}
    for e in PROCESS_EVENTS + NOTE_EVENTS:
        group[e] = "процесс"
    order = {e: i for i, e in enumerate(("conn_end", "assoc_end", "account_minute") + PROCESS_EVENTS + NOTE_EVENTS)}
    rows = [[e, group.get(e, "прочее"), n] for e, n in sorted(j.events.items(), key=lambda kv: (order.get(kv[0], 99), kv[0]))]
    out += ["### Строки по видам", ""] + table(["event", "вид", "строк"], rows, right={2})

    rows = []
    for t, d, event in sorted(j.proc, key=lambda x: x[0]):
        if event == "process_start":
            what = (f"version={text(d, 'version')} session_log={text(d, 'session_log')} "
                    f"transports={text(d, 'transports')} prev_unclean={yes_no(d.get('prev_unclean'))}")
        elif event == "process_stop":
            what = f"uptime={hms(num(d, 'uptime_s') * 1000)} conns={num(d, 'conns')} open={num(d, 'open')}"
        elif event == "config_reload":
            what = f"reload={num(d, 'reload')} failed={text(d, 'failed') or '-'}"
        else:
            what = f"dropped={num(d, 'dropped')}"
        rows.append([fmt_t(t, True), event, text(d, "boot") or "-", what])
    out += ["### События процесса", ""] + table(["время", "event", "boot", "детали"], rows)

    rows = [[a, b.conn, b.assoc, human(b.up), human(b.down)]
            for a, b in sorted(j.by_account.items(), key=lambda kv: (-(kv[1].conn + kv[1].assoc), kv[0]))]
    out += ["### Аккаунты", ""] + table(["аккаунт", "conn_end", "assoc_end", "up", "down"], rows, right={1, 2, 3, 4})
    out += ["### Версии клиента (`client`)", ""]
    out += table(["client", "строк"], [[k, v] for k, v in ranked(j.clients)], right={1})
    out += ["### Транспорты", ""]
    out += table(["transport", "строк"], [[k, v] for k, v in ranked(j.transports)], right={1})


def section_hours(j, out):
    out += ["## 2. По часам и аккаунтам", "",
            "`end` - единая причина конца; `минут conns` - сумма `conns` из `account_minute` за час (все `conn_end` и "
            "`assoc_end`, в том числе не попавшие в журнал при `abnormal`). Время часа - начало часа. `account_minute` пишется в "
            "конце минуты, которую считает, поэтому минута 12:59 попадает в час 13:00 колонки `минут conns`.", ""]
    rows = []
    for (hour, account) in sorted(j.by_hour):
        b = j.by_hour[(hour, account)]
        rows.append([fmt_t(hour), account, b.conn, b.assoc, ends(b.conn_end), ends(b.assoc_end),
                     human(b.up), human(b.down), b.minute_conns])
    out += table(["час", "аккаунт", "conn_end", "assoc_end", "end (conn_end)", "end (assoc_end)", "up", "down",
                  "минут conns"], rows, right={2, 3, 6, 7, 8})


def path_dead(row):
    """The path looked dead at a server_timeout. tcp_unacked is 1 on an idle stream: the relay half-closes before
    Close, and the snapshot finds the server's own FIN not yet acknowledged."""
    return row.get("tcp_retransmits", 0) > 0 or row.get("tcp_unacked", 0) > 1


def tcp_stats(j, cluster_minutes):
    """(end, in a cluster) -> lines, lines with tcp_*, lines that looked dead, values by field."""
    stats = {}
    for end, minute, values in j.silent:
        g = stats.setdefault((end, minute in cluster_minutes),
                             dict(lines=0, have=0, dead=0, vals=defaultdict(list)))
        g["lines"] += 1
        row = {k: v for (k, _), v in zip(TCP_FIELDS, values) if v is not None}
        if not row:
            continue
        g["have"] += 1
        for k, v in row.items():
            g["vals"][k].append(v)
        if end == "server_timeout" and path_dead(row):
            g["dead"] += 1
    return stats


def tcp_rows(stats, end, fields):
    empty = dict(vals={})
    rows = []
    for k in fields:
        row = [TCP_LABEL[k]]
        for in_cluster in (True, False):
            v = stats.get((end, in_cluster), empty)["vals"].get(k, [])
            row += [len(v), fnum(statistics.median(v)) if v else "-", fnum(max(v)) if v else "-"]
        rows.append(row)
    return rows


def section_clusters(j, out):
    o = j.opts
    out += ["## 3. Кластеры молчаливых концов", "",
            f"Минуты, в которые `server_timeout` или `reset` были у {o.cluster_accounts} и более аккаунтов. "
            "`st` - `server_timeout`, `rs` - `reset`. Строка `account_minute` пишется в конце минуты, которую считает, "
            "поэтому ее минута сдвинута относительно минуты `conn_end` на часть минуты. Сначала минуты с наибольшим "
            f"числом аккаунтов, при равенстве - раньшие; показано не больше {o.top}.", ""]
    rows, cluster_minutes = clusters(j.min_conn, o.cluster_accounts)
    out += [f"### По строкам conn_end и assoc_end (кластеров {len(rows)}, показано {min(len(rows), o.top)})", ""]
    out += table(["минута", "аккаунтов", "server_timeout", "reset", "по аккаунтам"], by_accounts(rows, o.top),
                 right={1, 2, 3})
    rows, _ = clusters(j.min_acct, o.cluster_accounts)
    out += [f"### По минутным счетчикам account_minute (кластеров {len(rows)}, показано {min(len(rows), o.top)})", ""]
    out += table(["минута", "аккаунтов", "server_timeout", "reset", "по аккаунтам"], by_accounts(rows, o.top),
                 right={1, 2, 3})

    out += ["### Состояние сокета (`tcp_*`) у молчаливых концов", "",
            "Снимок `TCP_INFO` берется перед закрытием. Судят только `server_timeout`: путь выглядел мертвым при "
            "`tcp_retransmits` > 0 или `tcp_unacked` > 1; единица в `tcp_unacked` - собственный FIN сервера, "
            "который релей отправляет перед Close и который к снимку еще не подтвержден. У `reset` и у "
            "`assoc_end` с `end=timeout` `tcp_unacked` не показан и вывода о пути нет, только числа: сброс мог "
            "прийти от цели, таймаут ассоциации - от дедлайна на живом сокете, а после `ETIMEDOUT` ядра очередь "
            "отправки уже пуста.", ""]
    stats = tcp_stats(j, cluster_minutes)
    if not j.silent:
        out += ["Таких строк нет.", ""]
    for end, title, fields in TCP_VIEWS:
        if not any(e == end for e, _, _ in j.silent):
            continue
        out += [f"#### {title}", ""]
        out += table(["поле", "кластеры: n", "медиана", "максимум", "вне кластеров: n", "медиана", "максимум"],
                     tcp_rows(stats, end, fields), right={1, 2, 3, 4, 5, 6})
        for in_cluster, name in ((True, "в кластерах"), (False, "вне кластеров")):
            g = stats.get((end, in_cluster))
            if not g:
                continue
            line = f"- {name}: строк {g['lines']}, из них с `tcp_*` {g['have']}"
            if end == "server_timeout":
                line += (f"; путь выглядел мертвым (`tcp_retransmits` > 0 или `tcp_unacked` > 1): {g['dead']}; "
                         f"иначе (клиент молчал): {g['have'] - g['dead']}")
            out.append(line + ".")
        out.append("")

    out += ["### silent_burst и udp_rcvbuf_drops", "",
            "`silent_burst` пишется только в служебный лог, в журнале его нет: строки появятся здесь, если "
            "передать файл служебного лога ключом `--service-log` (из него берутся только строки `silent_burst`). "
            "`udp_rcvbuf_drops` привязан к `account_minute` той же минуты: в последней колонке аккаунты с "
            "ассоциациями в ней.", ""]
    rows = []
    for rec in sorted(j.notes, key=lambda r: r["t"]):
        d = rec["d"]
        if rec["event"] == "udp_rcvbuf_drops":
            what = f"rcvbuf_drops={num(d, 'rcvbuf_drops')}"
        else:
            what = f"server_timeouts={num(d, 'server_timeouts')} conns={num(d, 'conns')}"
        linked = "; ".join(f"{a}: assocs={n} up={human(u)} down={human(dn)}" for a, n, u, dn in rec["accounts"])
        rows.append([fmt_t(rec["t"], True), rec["event"], text(d, "level") or "-", what, linked])
    out += table(["время", "event", "level", "числа", "ассоциации в ту минуту"], rows)


def section_dial(j, out):
    o = j.opts
    out += ["## 4. Dial", ""]
    if not j.dial_n:
        out.extend(["В журнале нет строк с dial (`dial_tries`).", ""])
        return
    ms = sorted(j.dials)
    slow = j.slow.count
    n_timeouts = sum(j.dial_timeouts.values())
    measured = (f"; `dial_ms`: p50 {fnum(percentile(ms, .5))}, p95 {fnum(percentile(ms, .95))}, max {fnum(ms[-1])}"
                f" (замер есть у {len(ms)})" if ms else "; ни у одного нет `dial_ms`")
    out += [f"- Соединений с dial: {j.dial_n}{measured}.",
            f"- Медленных (`dial_ms` > {o.slow_dial_ms}): {slow} ({pct(slow, len(ms))} от замеренных).",
            f"- `dial_timeout`: {n_timeouts}" + (f" ({', '.join(f'{a}: {n}' for a, n in ranked(j.dial_timeouts))})"
                                                  if n_timeouts else "") + ".",
            f"- С запасными сокетами (`dial_backups` > 0): {j.backups[0]}; запасных сокетов всего {j.backups[1]}; "
            f"соединение дал запасной (`dial_backup_won`): {j.backups[2]}.", ""]
    out += [f"### Самые медленные dial (показано {min(o.top, slow)} из {slow})", ""]
    rows = []
    for t, d, end in j.slow.items():
        rows.append([fmt_t(t, True), text(d, "account") or "-", text(d, "transport") or "-",
                     f"{text(d, 'dst_net') or '-'}:{fnum(num(d, 'dst_port', '-'))}", num(d, "dial_ms"),
                     num(d, "dial_tries"), num(d, "dial_backups"), "да" if d.get("dial_backup_won") is True else "нет",
                     end])
    out += table(["завершено", "аккаунт", "transport", "назначение (сеть:порт)", "dial_ms", "tries", "backups",
                  "запасной выиграл", "end"], rows, right={4, 5, 6})
    out += [f"### Назначения по сети и порту (только с медленными, таймаутами или запасными сокетами; "
            f"показано до {o.top})", ""]
    if all(k[0] == "-" for k in j.dst):
        out += ["В строках нет `dst_net` (`SESSION_LOG_DST=none`).", ""]
        return
    keyed = [(k, r) for k, r in j.dst.items() if r[1] or r[2] or r[3]]
    keyed.sort(key=lambda kr: (-(kr[1][1] + kr[1][2]), -kr[1][3], kr[0]))
    rows = [[f"{k[0]}:{'-' if k[1] == NO_PORT else k[1]}", r[0], r[1], pct(r[1], r[0]), r[2], r[3]]
            for k, r in keyed[:o.top]]
    out += table(["сеть:порт", "dial", f"медленных (> {o.slow_dial_ms})", "доля", "dial_timeout", "с запасными"],
                 rows, right={1, 2, 3, 4, 5})


def section_long(j, out):
    o = j.opts
    out += ["## 5. Длинные потоки", "",
            f"Соединения `conn_end` длиннее {o.long_s} с: {j.long.count}"
            + (f"; `end`: {ends(j.long_ends)}" if j.long.count else "") + ".", ""]
    rows = []
    for t, d, end in j.long.items():
        rows.append([fmt_t(t, True), hms(num(d, "dur_ms")), text(d, "account") or "-", text(d, "transport") or "-",
                     text(d, "cmd") or "-", f"{text(d, 'dst_net') or '-'}:{fnum(num(d, 'dst_port', '-'))}", end,
                     human(num(d, "up")), human(num(d, "down"))])
    out += table(["завершено", "длительность", "аккаунт", "transport", "cmd", "назначение (сеть:порт)", "end",
                  "up", "down"], rows, right={7, 8})


def section_udp(j, out):
    o = j.opts
    out += ["## 6. UDP-ассоциации", ""]
    if not j.assoc_cmd:
        out.extend(["В журнале нет `assoc_end`.", ""])
        return
    rows = []
    for cmd, c in sorted(j.assoc_cmd.items()):
        rows.append([cmd, c["n"], ends(j.assoc_ends[cmd]), c["dgram_up"], c["dgram_down"], human(c["up"]),
                     human(c["down"]), f"{c['rotated']} (ответ был: {c['answered']})"])
    out += ["### По видам ассоциации", ""]
    out += table(["cmd", "ассоциаций", "end", "dgram_up", "dgram_down", "up", "down",
                  "со сменой сокета (`rotations`)"], rows, right={1, 3, 4, 5, 6})

    n = j.native
    out += ["### Путь native", ""]
    if not n["n"]:
        out.extend(["Ассоциаций `cmd=native` нет.", ""])
        return
    out += [f"- Ассоциаций native: {n['n']}; датаграмм native вверх {n['up']}, вниз {n['down']}, "
            f"доля native от `dgram_up`+`dgram_down`: {pct(n['up'] + n['down'], n['dgrams'])}.",
            f"- `path_moves` всего {n['moves']} (ассоциаций с переходом ответов на поток: {n['moved']}); "
            f"`tunnel_drops` всего {n['drops']} (ассоциаций с потерями на потоке: {n['dropped']}).",
            f"- Не удержали native: {j.flagged.count}. Признаки: `path_moves` > 0, `tunnel_drops` > 0, `low_native` "
            f"(доля native ниже {o.native_share:g} при {MIN_DGRAMS} и более датаграммах).", ""]
    rows = []
    for t, d, e, reasons, share in j.flagged.items():
        rows.append([fmt_t(t, True), text(d, "account") or "-", hms(num(d, "dur_ms")), e,
                     f"{num(d, 'dgram_up')}/{num(d, 'dgram_down')}", f"{num(d, 'native_up')}/{num(d, 'native_down')}",
                     "-" if share is None else f"{100 * share:.0f}%", num(d, "path_moves"), num(d, "tunnel_drops"),
                     ", ".join(reasons)])
    out += [f"### Ассоциации, где native не удержался (показано {len(rows)} из {j.flagged.count})", ""]
    out += table(["завершено", "аккаунт", "длительность", "end", "dgram up/down", "native up/down", "доля native",
                  "path_moves", "tunnel_drops", "признаки"], rows, right={7, 8})


def section_client(j, client, out):
    out += ["## 7. Склейка с логом клиента", ""]
    if client is None:
        out.extend(["Лог клиента не передан (`--client-log`).", ""])
        return
    found = len(j.matched)
    out += [f"- Строк лога клиента: {client.lines}; из них `TCP Tunnel closed`: {client.tcp}, "
            f"с `conn` и временем: {len(client.conns)}.",
            f"- Найдено среди `conn_end` по `conn`: {found} ({pct(found, len(client.conns))}). Не найдено: "
            f"{len(client.conns) - found}: соединение вне периода журнала, при `abnormal` - не записанное, "
            "на plain-слушателе `conn` у сервера случайный.", ""]
    rows = []
    severity = {v: i for i, v in enumerate(reversed(VERDICTS))}
    for (by, end), n in sorted(j.pairs.items(), key=lambda kv: (severity[judge(*kv[0])], -kv[1], kv[0])):
        rows.append([by, end, n, judge(by, end)])
    out += ["### closed_by клиента и end сервера", "",
            "Колонка `оценка` - правила скрипта (таблица `AGREEMENT`), по `closed_by` клиента: "
            f"`{CONTRADICTION}` - эти два конца не могут быть одним событием (клиент пишет `app`, `tunnel_error` и "
            "`timeout` только после успешного ответа на CONNECT, отказ установки пишет как `server`); "
            f"`{POSSIBLE}` - гонка (одна сторона "
            "закрыла раньше, чем другая заметила), потерянный FIN, ошибка сокета самого приложения (`app`) или "
            "мертвый путь (`timeout` у клиента после `TUNNEL_DEAD_TIMEOUT` сочетается с любым концом, случившимся на "
            f"сервере раньше). Не названные ниже `end` - `{POSSIBLE}`.", ""]
    out += agreement_lines() + [""]
    out += table(["closed_by клиента", "end сервера", "соединений", "оценка"], rows, right={2})

    timeouts = sum(c.closed_by == "timeout" for c in client.conns.values())
    shown = j.client_timeouts.items()
    out += [f"### Соединения с closed_by=timeout у клиента: {timeouts}, найдено в журнале {j.client_timeouts.count} "
            f"(показаны самые поздние, {len(shown)})", ""]
    rows = [[fmt_t(t, True), conn, account, end, hms(srv), hms(cli)] for t, conn, account, end, srv, cli in shown]
    out += table(["время (клиент)", "conn", "аккаунт", "end сервера", "длительность сервера", "длительность клиента"], rows)


def section_sources(j, files, client, service, out):
    out += ["## 8. Источники и пропуски", ""]
    rows = [[f.name, f.lines, f.error or "ок"] for f in files]
    out += ["### Файлы журнала", ""] + table(["файл", "непустых строк", "чтение"], rows, right={1})
    if service:
        rows = [[f.name, f.lines, f.error or "ок"] for f in service]
        out += ["### Файлы служебного лога", ""] + table(["файл", "строк silent_burst", "чтение"], rows, right={1})
    if client:
        rows = [[f.name, f.lines, f.error or "ок"] for f in client.files]
        out += ["### Файлы лога клиента", ""] + table(["файл", "непустых строк JSON", "чтение"], rows, right={1})
    skipped = j.skipped + (client.skipped if client else Counter())
    out += ["### Пропущенные строки", ""]
    out += table(["причина", "строк"], [[k, v] for k, v in ranked(skipped)], right={1})
    bad = j.bad + (client.bad if client else Counter())
    out += ["### Числовые поля с нечисловым значением", "",
            "Значение читается как отсутствующее (0 или пусто); строка при этом не пропущена.", ""]
    out += table(["поле", "строк"], [[k, v] for k, v in ranked(bad)], right={1})
    out += ["### Поля вне закрытого набора журнала", ""]
    if j.unknown:
        out += ["Строки с такими полями разобраны, поля не использованы (кроме `closed_by` и `reason` у журнала "
                "старого формата).", ""]
    out += table(["поле", "строк"], [[k[:40], v] for k, v in ranked(j.unknown, 20)], right={1})


def render(j, client, files, service=()):
    j.link_drops()
    out = ["# Отчет по журналу сессий S5Core", ""]
    section_summary(j, out)
    if j.lines:
        section_hours(j, out)
        section_clusters(j, out)
        section_dial(j, out)
        section_long(j, out)
        section_udp(j, out)
        section_client(j, client, out)
    section_sources(j, files, client, service, out)
    return "\n".join(out).rstrip("\n") + "\n"


def whole_number(low):
    def parse(value):
        try:
            n = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"нужно целое число, получено {value!r}") from None
        if n < low:
            raise argparse.ArgumentTypeError(f"нужно целое число не меньше {low}, получено {value}")
        return n
    return parse


at_least_one = whole_number(1)
not_negative = whole_number(0)


def fraction(value):
    try:
        x = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"нужно число от 0 до 1, получено {value!r}") from None
    if not 0 <= x <= 1:
        raise argparse.ArgumentTypeError(f"нужно число от 0 до 1, получено {value}")
    return x


def distinct(paths):
    """The paths without the repeats of one file, in the order given."""
    seen, out = set(), []
    for path in paths:
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            out.append(path)
    return out


def build_parser():
    ap = argparse.ArgumentParser(
        description="Markdown-отчет по журналу сессий S5Core (SESSION_LOG_FILE). Читает только переданные файлы, "
                    "в сеть не ходит. Время в отчете в UTC и МСК (+3).",
        epilog="Разделы: 1 сводка, 2 по часам и аккаунтам, 3 кластеры, 4 dial, 5 длинные потоки, "
               "6 UDP-ассоциации, 7 склейка с логом клиента, 8 источники и пропуски.")
    ap.add_argument("journal", nargs="+", metavar="FILE",
                    help="файл журнала: JSONL или .gz (в том числе ротированные); порядок не важен")
    ap.add_argument("--client-log", action="append", default=[], metavar="FILE",
                    help="JSON-лог s5client со строками 'TCP Tunnel closed'; ключ можно повторить для файлов archive/")
    ap.add_argument("--service-log", action="append", default=[], metavar="FILE",
                    help="служебный лог сервера: из него берутся только строки silent_burst (в журнал они не "
                         "пишутся); ключ можно повторить")
    ap.add_argument("--slow-dial-ms", type=not_negative, default=800, metavar="MS", help="порог медленного dial (800)")
    ap.add_argument("--long-s", type=not_negative, default=1800, metavar="S", help="порог длинного потока, секунды (1800)")
    ap.add_argument("--top", type=at_least_one, default=10, metavar="N", help="длина топ-списков (10)")
    ap.add_argument("--cluster-accounts", type=at_least_one, default=2, metavar="N",
                    help="сколько аккаунтов в одной минуте делают ее кластером (2)")
    ap.add_argument("--native-share", type=fraction, default=0.8, metavar="X",
                    help="ниже этой доли native от датаграмм ассоциация считается не удержавшей путь (0.8)")
    return ap


def main(argv=None):
    opts = build_parser().parse_args(argv)
    client_logs = distinct(opts.client_log)
    client = ClientLog(client_logs) if client_logs else None
    j = Journal(opts, client)
    files = []
    for path in distinct(opts.journal):
        info = FileInfo(os.path.basename(path))
        files.append(info)
        for raw in read_lines(path, info):
            if raw.strip():
                info.lines += 1
            j.feed(raw)
    service = []
    for path in distinct(opts.service_log):
        info = FileInfo(os.path.basename(path))
        service.append(info)
        for raw in read_lines(path, info):
            j.feed_service(raw, info)
    out = sys.stdout
    if hasattr(out, "reconfigure"):
        out.reconfigure(encoding="utf-8")
    out.write(render(j, client, files, service))
    failed = any(f.error for f in files + service) or bool(client and any(f.error for f in client.files))
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
