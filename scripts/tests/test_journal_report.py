import contextlib
import gzip
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..")
sys.path.insert(0, SCRIPTS)

import journal_report as jr  # noqa: E402

BASE = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
SCRIPT = os.path.join(SCRIPTS, "journal_report.py")
GO_TEST = os.path.join(SCRIPTS, "..", "pkg", "s5server", "journal_test.go")

_seq = [0]


def at(minutes=0, seconds=0, hours=0, days=0):
    return BASE + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def line(event, t, level="INFO", **fields):
    _seq[0] += 1
    return json.dumps(dict(time=stamp(t), level=level, msg=event, event=event, seq=_seq[0], **fields))


def conn_end(t, conn, account="alice", end="client", **f):
    base = dict(conn=conn, account=account, auth="key", transport="obfs", client="2.3.0-rc6", cmd="connect",
                dst_net="198.51.100.0/24", dst_port=443, dst_kind="name", result="ok", end=end,
                dial_ms=120, dial_tries=1, dial_backups=0, dur_ms=5000, up=1000, down=5000)
    base.update(f)
    return line("conn_end", t, **base)


def assoc_end(t, conn, account="alice", end="client", **f):
    base = dict(conn=conn, account=account, auth="key", transport="obfs", client="2.3.0-rc6", cmd="native",
                result="ok", end=end, dur_ms=60000, up=20000, down=30000, dgram_up=100, dgram_down=100,
                native_up=100, native_down=100, path_moves=0, tunnel_drops=0)
    base.update(f)
    return line("assoc_end", t, **base)


def account_minute(t, account, **f):
    base = dict(account=account, conns=1, failed=0, assocs=0, dial_backups=0, server_timeouts=0, resets=0,
                up=0, down=0)
    base.update(f)
    return line("account_minute", t, **base)


def options(*extra):
    return jr.build_parser().parse_args(["x", *extra])


def analyze(lines, *extra):
    j = jr.Journal(options(*extra))
    for raw in lines:
        j.feed(raw)
    return j


def text(d, key):
    return jr.text(d, key)


def fmt(t):
    return jr.fmt_t(t)


def section_of(out, start, end=None):
    i = out.index(start)
    return out[i:out.index(end, i + len(start))] if end else out[i:]


class Files(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def write(self, name, lines, gz=False):
        path = os.path.join(self.dir, name)
        data = ("\n".join(lines) + "\n").encode()
        if gz:
            data = gzip.compress(data)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def run_main(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = jr.main(list(argv))
        return rc, buf.getvalue()


class Basics(unittest.TestCase):
    def test_times_are_read_in_every_form_slog_and_the_journal_write(self):
        want = datetime(2026, 10, 1, 12, 34, 56, 789000, tzinfo=timezone.utc)
        for s in ("2026-10-01T12:34:56.789Z", "2026-10-01T12:34:56.789000000Z", "2026-10-01T15:34:56.789+03:00",
                  "2026-10-01T15:34:56.789+0300", "2026-10-01 12:34:56.789"):
            self.assertEqual(jr.parse_time(s), want, s)
        self.assertEqual(jr.parse_time("2026-10-01T12:34:56Z"), datetime(2026, 10, 1, 12, 34, 56, tzinfo=timezone.utc))
        for bad in ("", None, 5, "yesterday", "2026-13-01T00:00:00Z", "2026-10-01T12:34:56.Z", "2026-10-01T12:34:56+3",
                    "9999-12-31T23:59:59Z", "２０２６-10-01T12:34:56Z"):
            self.assertIsNone(jr.parse_time(bad), bad)

    def test_both_zones_are_written_and_the_date_follows_moscow(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        self.assertEqual(jr.fmt_t(t, True), "2026-10-01 21:30:15 UTC / 2026-10-02 00:30:15 МСК")
        self.assertEqual(jr.fmt_t(at(), False), "2026-10-01 12:00 UTC / 15:00 МСК")

    def test_the_known_fields_are_the_ones_the_server_may_write(self):
        if not os.path.exists(GO_TEST):
            self.skipTest("pkg/s5server/journal_test.go is not next to the script")
        with open(GO_TEST, encoding="utf-8") as f:
            src = f.read()
        block = src[src.index("var journalFields"):]
        block = block[:block.index("\n}\n")]
        self.assertEqual(set(re.findall(r'"(\w+)": true', block)), set(jr.KNOWN_FIELDS))


class Reading(Files):
    def test_an_empty_input_gives_a_report_and_no_error(self):
        empty = self.write("empty.jsonl", [])
        blank = self.write("blank.jsonl", ["", "   ", ""])
        for path in (empty, blank):
            rc, out = self.run_main(path)
            self.assertEqual(rc, 0)
            self.assertIn("Строк журнала нет.", out)
            self.assertIn("## 8. Источники и пропуски", out)
        self.assertEqual(jr.Journal(options()).lines, 0)

    def test_a_missing_file_is_named_and_the_rest_is_still_read(self):
        good = self.write("a.jsonl", [conn_end(at(1), "c1")])
        rc, out = self.run_main(os.path.join(self.dir, "nope.jsonl"), good)
        self.assertEqual(rc, 1)
        self.assertIn("FileNotFoundError", out)
        self.assertIn("conn_end", out)

    def test_broken_lines_are_counted_and_do_not_stop_the_report(self):
        good = conn_end(at(1), "c1")
        torn = conn_end(at(2), "c2")[:60]
        j = analyze([
            good, "this is not json", torn, "[1, 2]", "42", '{"time": "2026-10-01T12:00:00.000Z"}',
            '{"event": "conn_end", "time": "yesterday"}', '{"event": 5, "time": "2026-10-01T12:00:00.000Z"}',
            line("conn_end", at(3), conn="c3", account="bob", end="reset", surprise=1, other="x"),
            "[" * 100000,
        ])
        self.assertEqual(j.lines, 2)
        self.assertEqual(sum(j.skipped.values()), 8)
        self.assertEqual(j.skipped["нет поля event"], 2)
        self.assertEqual(j.skipped["нет корректного time"], 1)
        self.assertEqual(j.skipped["JSON, но не объект"], 2)
        self.assertEqual(dict(j.unknown), {"surprise": 1, "other": 1})
        path = self.write("broken.jsonl", ["not json", good, "{", line("conn_end", at(3), conn="c3", zzz=1)])
        rc, out = self.run_main(path)
        self.assertEqual(rc, 0)
        self.assertIn("| zzz | 1 |", out)
        self.assertIn("не JSON (в том числе оборванная строка) | 2 |", out)

    def test_rotated_gzip_and_plain_files_are_read_together(self):
        a = self.write("sessions-20260930T101500.000Z.jsonl.gz", [conn_end(at(1), "c1"), conn_end(at(2), "c2")], gz=True)
        b = self.write("sessions.jsonl", [conn_end(at(3), "c3", account="bob")])
        c = self.write("renamed-rotation", [conn_end(at(4), "c4")], gz=True)
        rc, out = self.run_main(a, b, c, a)
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"\| conn_end \| сессии \| 4 \|")
        self.assertRegex(out, r"\| alice \| 3 \| 0 \|")
        self.assertEqual(out.count("sessions-20260930T101500.000Z.jsonl.gz |"), 1)

    def test_a_truncated_gzip_keeps_what_it_gave_and_says_so(self):
        lines = [conn_end(at(0, i % 60), f"c{i}") for i in range(2000)]
        path = os.path.join(self.dir, "cut.jsonl.gz")
        data = gzip.compress(("\n".join(lines) + "\n").encode())
        with open(path, "wb") as f:
            f.write(data[:-30])
        rc, out = self.run_main(path)
        self.assertEqual(rc, 1)
        self.assertIn("EOFError", out)
        self.assertRegex(out, r"\| conn_end \| сессии \| \d+ \|")

    def test_an_invalid_utf8_byte_is_not_a_crash(self):
        path = os.path.join(self.dir, "bytes.jsonl")
        with open(path, "wb") as f:
            f.write(b'\xff\xfe\n' + conn_end(at(1), "c1").encode() + b"\n")
        rc, out = self.run_main(path)
        self.assertEqual(rc, 0)
        self.assertIn("conn_end", out)

    def test_an_older_journal_that_says_closed_by_or_reason_is_still_grouped(self):
        old_conn = json.dumps(dict(time=stamp(at(1)), event="conn_end", conn="c1", account="alice", closed_by="reset",
                                   result="ok"))
        old_assoc = json.dumps(dict(time=stamp(at(2)), event="assoc_end", conn="c2", account="alice", reason="timeout",
                                    cmd="tunnel", result="ok"))
        no_end = json.dumps(dict(time=stamp(at(3)), event="conn_end", conn="c3", account="alice", result="dial_timeout"))
        j = analyze([old_conn, old_assoc, no_end])
        b = j.by_account["alice"]
        self.assertEqual(dict(b.conn_end), {"reset": 1, "dial_timeout": 1})
        self.assertEqual(dict(b.assoc_end), {"timeout": 1})
        self.assertEqual(j.unknown["closed_by"], 1)


class Summary(Files):
    def test_the_report_names_the_period_the_kinds_the_accounts_and_the_builds(self):
        lines = [
            line("process_start", at(0), boot="b0000001", version="2.3.0-rc6", go_version="go1.26.6", pid=1,
                 transports="plain,obfs", session_log="all", prev_unclean=False),
            conn_end(at(1), "c1"), conn_end(at(2), "c2", account="bob", client="2.2.0", transport="ws"),
            assoc_end(at(3), "a1"), account_minute(at(4), "alice", conns=7),
            line("config_reload", at(5), boot="b0000001", reload=1),
            line("log_gap", at(6), level="WARN", dropped=12),
            line("process_stop", at(7), boot="b0000001", uptime_s=420, conns=2, open=0),
            line("minute", at(8), boot="b0000001", conns=2),
        ]
        rc, out = self.run_main(self.write("s.jsonl", lines))
        self.assertEqual(rc, 0)
        self.assertIn("Период: 2026-10-01 12:00:00 UTC / 15:00:00 МСК - 2026-10-01 12:08:00 UTC / 15:08:00 МСК", out)
        self.assertIn("Строк разобрано: 9", out)
        self.assertRegex(out, r"\| minute \| прочее \| 1 \|")
        self.assertRegex(out, r"\| process_stop \| процесс \| 1 \|")
        self.assertIn("version=2.3.0-rc6 session_log=all transports=plain,obfs prev_unclean=нет", out)
        self.assertIn("uptime=0:07:00 conns=2 open=0", out)
        self.assertIn("Строк потеряно писателем (`log_gap`): 12", out)
        self.assertRegex(out, r"\| 2\.3\.0-rc6 \| 2 \|")
        self.assertRegex(out, r"\| 2\.2\.0 \| 1 \|")
        self.assertRegex(out, r"\| ws \| 1 \|")

    def test_an_abnormal_journal_is_called_partial(self):
        lines = [line("process_start", at(0), boot="b", session_log="abnormal"), conn_end(at(1), "c1", end="reset")]
        _, out = self.run_main(self.write("s.jsonl", lines))
        self.assertIn("В журнале есть запуск с `session_log=abnormal`: `conn_end` записаны не для всех соединений",
                      out)
        _, out = self.run_main(self.write("t.jsonl", [line("process_start", at(0), boot="b", session_log="all")]))
        self.assertNotIn("записаны не для всех соединений", out)

    def test_prev_unclean_is_written_as_yes_no_or_a_dash(self):
        lines = [line("process_start", at(0), boot="b1", prev_unclean=True), line("process_start", at(1), boot="b2",
                                                                                   prev_unclean=False),
                 line("process_start", at(2), boot="b3")]
        _, out = self.run_main(self.write("s.jsonl", lines))
        for want in ("prev_unclean=да", "prev_unclean=нет", "prev_unclean=-"):
            self.assertEqual(out.count(want), 1, want)
        self.assertNotIn("prev_unclean=True", out)
        self.assertNotIn("prev_unclean=False", out)


class Hours(Files):
    def test_every_hour_and_account_has_its_counts_ends_bytes_and_minute_total(self):
        lines = [
            conn_end(at(5), "c1", end="client", up=1024, down=2048),
            conn_end(at(6), "c2", end="reset", up=1024, down=0),
            conn_end(at(7), "c3", account="bob", end="target"),
            assoc_end(at(8), "a1", end="timeout", up=0, down=0),
            conn_end(at(65), "c4", end="client"),
            account_minute(at(5, 30), "alice", conns=40),
            account_minute(at(65, 30), "alice", conns=2),
        ]
        _, out = self.run_main(self.write("s.jsonl", lines))
        self.assertIn("`account_minute` пишется в конце минуты, которую считает, поэтому минута 12:59 попадает в час "
                      "13:00 колонки `минут conns`", out)
        row = next(r for r in out.splitlines() if r.startswith("| 2026-10-01 12:00 UTC / 15:00 МСК | alice"))
        cols = [c.strip() for c in row.strip("|").split("|")]
        self.assertEqual(cols[2:], ["2", "1", "client=1 reset=1", "timeout=1", "2.0 КиБ", "2.0 КиБ", "40"])
        bob = next(r for r in out.splitlines() if r.startswith("| 2026-10-01 12:00 UTC / 15:00 МСК | bob"))
        self.assertIn("target=1", bob)
        self.assertTrue(any(r.startswith("| 2026-10-01 13:00 UTC / 16:00 МСК | alice") and "| 2 |" in r
                            for r in out.splitlines()))

    def test_a_minute_counter_written_just_after_the_hour_belongs_to_the_next_hour(self):
        j = analyze([account_minute(at(60) + timedelta(milliseconds=3), "alice", conns=9)])
        self.assertEqual(j.by_hour[(at(60), "alice")].minute_conns, 9)
        self.assertNotIn((at(), "alice"), j.by_hour)


class Clusters(Files):
    def lines(self):
        return [
            conn_end(at(5, 1), "c1", end="server_timeout", tcp_rtt_ms=40, tcp_unacked=0, tcp_retransmits=0,
                     tcp_since_data_ms=31000, tcp_since_ack_ms=100),
            conn_end(at(5, 2), "c2", end="server_timeout", tcp_rtt_ms=60, tcp_unacked=5, tcp_retransmits=2,
                     tcp_since_data_ms=32000, tcp_since_ack_ms=29000),
            conn_end(at(5, 3), "c3", account="bob", end="reset", tcp_rtt_ms=50, tcp_unacked=7, tcp_retransmits=3,
                     tcp_since_data_ms=1000, tcp_since_ack_ms=30000),
            conn_end(at(20, 1), "c4", end="server_timeout", tcp_rtt_ms=500, tcp_unacked=0, tcp_retransmits=0,
                     tcp_since_data_ms=30000, tcp_since_ack_ms=10),
            conn_end(at(20, 2), "c5", end="server_timeout"),
            conn_end(at(20, 3), "c6", end="server_timeout"),
            conn_end(at(30, 1), "c7", end="reset", tcp_rtt_ms=80, tcp_unacked=1, tcp_retransmits=1,
                     tcp_since_data_ms=2000, tcp_since_ack_ms=2000),
            assoc_end(at(30, 2), "a1", account="bob", end="reset", cmd="tunnel", tcp_rtt_ms=100, tcp_unacked=0,
                      tcp_retransmits=0, tcp_since_data_ms=3000, tcp_since_ack_ms=3000),
            conn_end(at(40, 1), "c8", end="client"),
            conn_end(at(40, 2), "c9", account="bob", end="target"),
            account_minute(at(6, 5), "alice", server_timeouts=2, resets=0),
            account_minute(at(6, 5), "bob", server_timeouts=0, resets=1),
            account_minute(at(21, 5), "alice", server_timeouts=3),
            account_minute(at(21, 5), "carol", conns=9),
        ]

    def test_a_minute_is_a_cluster_only_when_two_accounts_have_silent_ends(self):
        j = analyze(self.lines())
        rows, minutes = jr.clusters(j.min_conn, 2)
        self.assertEqual(minutes, {at(5), at(30)})
        self.assertEqual([r[1:4] for r in rows], [[2, 2, 1], [2, 0, 2]])
        self.assertIn("alice: st=2 rs=0; bob: st=0 rs=1", rows[0][4])
        rows, minutes = jr.clusters(j.min_acct, 2)
        self.assertEqual(minutes, {at(6)})
        self.assertEqual(rows[0][1:4], [2, 2, 1])
        rows, _ = jr.clusters(j.min_conn, 1)
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(jr.clusters(j.min_conn, 3)[0]), 0)

    def test_only_a_server_timeout_with_retransmits_or_more_than_its_own_fin_unacked_looks_dead(self):
        self.assertFalse(jr.path_dead({}))
        self.assertFalse(jr.path_dead({"tcp_unacked": 0, "tcp_retransmits": 0}))
        self.assertFalse(jr.path_dead({"tcp_unacked": 1, "tcp_retransmits": 0}))
        self.assertTrue(jr.path_dead({"tcp_unacked": 2}))
        self.assertTrue(jr.path_dead({"tcp_unacked": 1, "tcp_retransmits": 1}))
        self.assertTrue(jr.path_dead({"tcp_retransmits": 1}))

    def test_the_socket_state_of_the_cluster_is_summed_up_apart_from_the_rest(self):
        j = analyze(self.lines())
        _, minutes = jr.clusters(j.min_conn, 2)
        stats = jr.tcp_stats(j, minutes)
        rows = {r[0]: r for r in jr.tcp_rows(stats, "server_timeout", [k for k, _ in jr.TCP_FIELDS])}
        self.assertEqual(rows["rtt, мс"][1:], [2, "50", "60", 1, "500", "500"])
        self.assertEqual(rows["unacked"][1:], [2, "2.5", "5", 1, "0", "0"])
        self.assertEqual(rows["since_ack, мс"][1:], [2, "14550", "29000", 1, "10", "10"])
        st_in, st_out = stats[("server_timeout", True)], stats[("server_timeout", False)]
        self.assertEqual((st_in["lines"], st_in["have"], st_in["dead"]), (2, 2, 1))
        self.assertEqual((st_out["lines"], st_out["have"], st_out["dead"]), (3, 1, 0))
        resets = {r[0]: r for r in jr.tcp_rows(stats, "reset", ("tcp_retransmits", "tcp_since_ack_ms"))}
        self.assertEqual(sorted(resets), ["retransmits", "since_ack, мс"])
        self.assertEqual(resets["retransmits"][1:], [3, "1", "3", 0, "-", "-"])
        self.assertEqual(stats[("reset", True)]["dead"], 0)

    def test_the_report_lists_the_cluster_minutes_and_not_the_single_account_one(self):
        _, out = self.run_main(self.write("s.jsonl", self.lines()))
        section = section_of(out, "## 3.", "## 4.")
        self.assertIn("| 2026-10-01 12:05 UTC / 15:05 МСК | 2 | 2 | 1 |", section)
        self.assertIn("| 2026-10-01 12:30 UTC / 15:30 МСК | 2 | 0 | 2 |", section)
        self.assertIn("| 2026-10-01 12:06 UTC / 15:06 МСК | 2 | 2 | 1 |", section)
        self.assertNotIn("12:20 UTC", section)
        self.assertNotIn("12:21 UTC", section)

    def test_only_a_server_timeout_is_judged_and_a_reset_shows_two_fields(self):
        _, out = self.run_main(self.write("s.jsonl", self.lines()))
        section = section_of(out, "### Состояние сокета", "### silent_burst")
        self.assertIn("единица в `tcp_unacked` - собственный FIN сервера", section)
        st = section_of(section, "#### server_timeout", "#### reset")
        self.assertIn("- в кластерах: строк 2, из них с `tcp_*` 2; путь выглядел мертвым (`tcp_retransmits` > 0 или "
                      "`tcp_unacked` > 1): 1; иначе (клиент молчал): 1.", st)
        self.assertIn("- вне кластеров: строк 3, из них с `tcp_*` 1; путь выглядел мертвым (`tcp_retransmits` > 0 или "
                      "`tcp_unacked` > 1): 0; иначе (клиент молчал): 1.", st)
        for name in ("rtt, мс", "unacked", "retransmits", "since_data, мс", "since_ack, мс"):
            self.assertIn(f"| {name} |", st)
        rs = section_of(section, "#### reset", None)
        self.assertIn("- в кластерах: строк 3, из них с `tcp_*` 3.", rs)
        self.assertNotIn("выглядел мертвым", rs)
        self.assertIn("| retransmits |", rs)
        self.assertIn("| since_ack, мс |", rs)
        for name in ("rtt, мс", "unacked", "since_data, мс"):
            self.assertNotIn(f"| {name} |", rs)

    def test_a_server_timeout_with_only_its_own_fin_unacked_is_counted_as_quiet(self):
        lines = [conn_end(at(1, i), f"c{i}", end="server_timeout", tcp_rtt_ms=20, tcp_unacked=1, tcp_retransmits=0,
                          tcp_since_data_ms=30000, tcp_since_ack_ms=30000) for i in range(3)]
        lines.append(conn_end(at(2), "d1", end="server_timeout", tcp_rtt_ms=20, tcp_unacked=2, tcp_retransmits=0,
                              tcp_since_data_ms=30000, tcp_since_ack_ms=30000))
        _, out = self.run_main(self.write("s.jsonl", lines))
        self.assertIn("- вне кластеров: строк 4, из них с `tcp_*` 4; путь выглядел мертвым (`tcp_retransmits` > 0 или "
                      "`tcp_unacked` > 1): 1; иначе (клиент молчал): 3.", out)

    def test_the_tcp_state_of_an_association_timeout_is_its_own_group(self):
        lines = [
            conn_end(at(1), "c1", end="server_timeout", tcp_rtt_ms=10, tcp_unacked=0, tcp_retransmits=0,
                     tcp_since_data_ms=1, tcp_since_ack_ms=1),
            assoc_end(at(2), "a1", cmd="tunnel", end="timeout", tcp_rtt_ms=70, tcp_unacked=0, tcp_retransmits=4,
                      tcp_since_data_ms=5000, tcp_since_ack_ms=9000),
            assoc_end(at(3), "a2", cmd="tunnel", end="client", tcp_retransmits=99),
        ]
        _, out = self.run_main(self.write("s.jsonl", lines))
        section = section_of(out, "### Состояние сокета", "### silent_burst")
        group = section_of(section, "#### timeout (assoc_end)", None)
        self.assertIn("| retransmits | 0 | - | - | 1 | 4 | 4 |", group)
        self.assertIn("| since_ack, мс | 0 | - | - | 1 | 9000 | 9000 |", group)
        self.assertNotIn("выглядел мертвым", group)
        st = section_of(section, "#### server_timeout", "#### timeout")
        self.assertIn("| rtt, мс | 0 | - | - | 1 | 10 | 10 |", st)
        self.assertNotIn("99", section)

    def test_without_silent_ends_the_tcp_section_says_so(self):
        _, out = self.run_main(self.write("s.jsonl", [conn_end(at(1), "c1")]))
        self.assertIn("Таких строк нет.", section_of(out, "### Состояние сокета", "### silent_burst"))
        self.assertNotIn("#### ", out)

    def test_the_cluster_tables_are_sorted_by_accounts_then_time_and_cut_by_top(self):
        lines = []
        for minute, accounts in ((1, 2), (2, 4), (3, 3), (4, 4), (5, 2)):
            for n in range(accounts):
                lines.append(conn_end(at(minute, n), f"c{minute}-{n}", account=f"acc{n}", end="reset"))
        j = analyze(lines)
        rows, _ = jr.clusters(j.min_conn, 2)
        self.assertEqual([r[1] for r in rows], [2, 4, 3, 4, 2])
        cut = jr.by_accounts(rows, 3)
        self.assertEqual([(r[0], r[1]) for r in cut], [(fmt(at(2)), 4), (fmt(at(4)), 4), (fmt(at(3)), 3)])
        self.assertEqual(len(jr.by_accounts(rows, 99)), 5)
        _, out = self.run_main(self.write("s.jsonl", lines), "--top", "3")
        section = section_of(out, "### По строкам conn_end", "### По минутным")
        self.assertIn("(кластеров 5, показано 3)", section)
        self.assertEqual(sorted(re.findall(r"12:0(\d) UTC", section)), ["2", "3", "4"])
        self.assertLess(section.index("12:02 UTC"), section.index("12:04 UTC"))
        self.assertLess(section.index("12:04 UTC"), section.index("12:03 UTC"))
        self.assertIn("при равенстве - раньшие; показано не больше 3", out)

    def test_silent_burst_and_drops_are_listed_with_both_times_and_the_accounts_of_that_minute(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        lines = [
            line("silent_burst", t, level="WARN", boot="b", server_timeouts=5, conns=12),
            line("udp_rcvbuf_drops", t, level="WARN", boot="b", rcvbuf_drops=75),
            account_minute(t + timedelta(milliseconds=3), "alice", assocs=2, up=2048, down=4096),
            account_minute(t + timedelta(milliseconds=4), "bob", assocs=0),
            account_minute(t + timedelta(seconds=40), "carol", assocs=3),
        ]
        _, out = self.run_main(self.write("s.jsonl", lines))
        section = out[out.index("### silent_burst"):out.index("## 4.")]
        self.assertIn("| 2026-10-01 21:30:15 UTC / 2026-10-02 00:30:15 МСК | silent_burst | WARN | "
                      "server_timeouts=5 conns=12 | - |", section)
        self.assertIn("| udp_rcvbuf_drops | WARN | rcvbuf_drops=75 | alice: assocs=2 up=2.0 КиБ down=4.0 КиБ |", section)
        self.assertNotIn("bob", section)
        self.assertNotIn("carol", section)

    def test_the_drops_find_their_accounts_in_whichever_file_is_read_first(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        drops = self.write("drops.jsonl", [line("udp_rcvbuf_drops", t, level="WARN", boot="b", rcvbuf_drops=75)])
        minute = self.write("minute.jsonl", [account_minute(t + timedelta(milliseconds=3), "alice", assocs=2)])
        for order in ((drops, minute), (minute, drops)):
            _, out = self.run_main(*order)
            section = section_of(out, "### silent_burst", "## 4.")
            self.assertIn("| udp_rcvbuf_drops | WARN | rcvbuf_drops=75 | alice: assocs=2 up=0 Б down=0 Б |", section)

    def test_the_drops_take_the_lines_that_follow_them_in_time_order_and_not_the_ones_before(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        drops = self.write("drops.jsonl", [line("udp_rcvbuf_drops", t, level="WARN", boot="b", rcvbuf_drops=75)])
        after = self.write("after.jsonl", [account_minute(t + timedelta(milliseconds=9), "carol", assocs=1),
                                           account_minute(t + timedelta(milliseconds=3), "alice", assocs=2)])
        before = self.write("before.jsonl", [account_minute(t - timedelta(milliseconds=200), "dave", assocs=4)])
        for order in ((drops, after, before), (before, after, drops)):
            _, out = self.run_main(*order)
            section = section_of(out, "### silent_burst", "## 4.")
            self.assertIn("alice: assocs=2 up=0 Б down=0 Б; carol: assocs=1 up=0 Б down=0 Б |", section)
            self.assertNotIn("dave", section)

    def test_the_report_is_the_same_when_it_is_rendered_twice(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        j = jr.Journal(options())
        for raw in (line("udp_rcvbuf_drops", t, level="WARN", boot="b", rcvbuf_drops=75),
                    account_minute(t + timedelta(milliseconds=3), "alice", assocs=2)):
            j.feed(raw)
        self.assertEqual(jr.render(j, None, []), jr.render(j, None, []))

    def test_silent_burst_comes_only_from_the_service_log_option_and_only_those_lines(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        service = [
            line("silent_burst", t, level="WARN", boot="b", server_timeouts=5, conns=12),
            json.dumps(dict(time=stamp(t), level="INFO", msg="silent_burst is a word here", event="listen", leak="x")),
            json.dumps(dict(time=stamp(t), level="WARN", msg="other", event="other", server_timeouts=99)),
            "silent_burst but not json",
            json.dumps(dict(time=stamp(t), level="INFO", msg="Config", event="config", password="hunter2")),
        ]
        journal = self.write("s.jsonl", [conn_end(at(1), "c1")])
        _, out = self.run_main(journal)
        section = section_of(out, "### silent_burst", "## 4.")
        self.assertIn("`--service-log`", section)
        self.assertIn("Нет данных.", section)
        rc, out = self.run_main(journal, "--service-log", self.write("service.log", service))
        self.assertEqual(rc, 0)
        section = section_of(out, "### silent_burst", "## 4.")
        self.assertIn("| 2026-10-01 21:30:15 UTC / 2026-10-02 00:30:15 МСК | silent_burst | WARN | "
                      "server_timeouts=5 conns=12 | - |", section)
        self.assertNotIn("99", section)
        for secret in ("hunter2", "password", "leak"):
            self.assertNotIn(secret, out)
        self.assertIn("Строк разобрано: 1\n", out)
        self.assertIn("### Файлы служебного лога", out)
        self.assertIn("| service.log | 1 | ок |", out)

    def test_a_service_log_given_twice_counts_once_and_names_its_skips(self):
        t = datetime(2026, 10, 1, 21, 30, 15, tzinfo=timezone.utc)
        service = self.write("service.log", [
            line("silent_burst", t, level="WARN", boot="b", server_timeouts=5, conns=12),
            json.dumps(dict(time="never", level="WARN", msg="silent_burst", event="silent_burst")),
        ])
        journal = self.write("s.jsonl", [conn_end(at(1), "c1")])
        _, out = self.run_main(journal, "--service-log", service, "--service-log", service)
        self.assertEqual(out.count("| silent_burst | WARN |"), 1)
        self.assertIn("| служебный лог: нет корректного time | 1 |", out)

    def test_an_unreadable_service_log_is_named_and_fails_the_run(self):
        journal = self.write("s.jsonl", [conn_end(at(1), "c1")])
        rc, out = self.run_main(journal, "--service-log", os.path.join(self.dir, "none.log"))
        self.assertEqual(rc, 1)
        self.assertIn("FileNotFoundError", out)


class Dial(Files):
    def lines(self):
        return [
            conn_end(at(1), "c1", dial_ms=100),
            conn_end(at(2), "c2", dial_ms=900, dial_backups=1, dial_backup_won=True),
            conn_end(at(3), "c3", dial_ms=1200, dial_tries=2, dial_backups=2, dst_net="203.0.113.0/24", dst_port=8443),
            conn_end(at(4), "c4", account="bob", end="dial_timeout", result="dial_timeout", stage="dial", dial_ms=5000,
                     dst_net="203.0.113.0/24", dst_port=8443),
            conn_end(at(5), "c5", dial_ms=800),
            conn_end(at(6), "c6", end="auth_failed", result="auth_failed", dial_tries=0, dial_ms=0),
            assoc_end(at(7), "a1"),
        ]

    def test_slow_timeouts_and_backups_are_counted_by_the_threshold(self):
        j = analyze(self.lines())
        self.assertEqual(len(j.dials), 5)
        self.assertEqual(j.slow.count, 3)
        self.assertEqual(dict(j.dial_timeouts), {"bob": 1})
        self.assertEqual(j.backups, [2, 3, 1])
        self.assertEqual(analyze(self.lines(), "--slow-dial-ms", "1000").slow.count, 2)
        self.assertEqual(j.dst[("203.0.113.0/24", 8443)], [2, 2, 1, 1])

    def test_the_report_names_destinations_by_network_and_port_only(self):
        _, out = self.run_main(self.write("s.jsonl", self.lines()))
        section = out[out.index("## 4."):out.index("## 5.")]
        self.assertIn("(замер есть у 5)", section)
        self.assertIn("Медленных (`dial_ms` > 800): 3 (60.0% от замеренных)", section)
        self.assertIn("`dial_timeout`: 1 (bob: 1)", section)
        self.assertIn("запасных сокетов всего 3; соединение дал запасной (`dial_backup_won`): 1", section)
        self.assertIn("| 203.0.113.0/24:8443 | 2 | 2 | 100.0% | 1 | 1 |", section)
        self.assertIn("| 198.51.100.0/24:443 | 3 | 1 | 33.3% | 0 | 1 |", section)
        self.assertIn("| сеть:порт | dial |", section)
        slow = section_of(section, "### Самые медленные dial", "### Назначения")
        cells = [[c.strip() for c in r.strip("|").split("|")] for r in slow.splitlines() if r.startswith("| 2026-")]
        self.assertEqual(len(cells), 3)
        for row in cells:
            self.assertRegex(row[3], r"^\d+\.\d+\.\d+\.0/24:\d+$")
        self.assertLess(section.index("203.0.113.0/24:8443 |"), section.index("198.51.100.0/24:443 |"))

    def test_a_name_in_an_unknown_field_never_reaches_the_report(self):
        lines = [conn_end(at(1), "c1", dial_ms=2000, dst_host="secret.example.test")]
        _, out = self.run_main(self.write("s.jsonl", lines))
        self.assertIn("| dst_host | 1 |", out)
        self.assertNotIn("secret.example.test", out)

    def test_a_dial_timeout_without_dial_tries_adds_no_zero_to_the_percentiles(self):
        lines = [
            conn_end(at(1), "c1", dial_ms=300),
            line("conn_end", at(2), conn="c2", account="bob", end="dial_timeout", result="dial_timeout", stage="dial"),
        ]
        j = analyze(lines)
        self.assertEqual((j.dial_n, j.dials), (2, [300]))
        self.assertEqual(dict(j.dial_timeouts), {"bob": 1})
        _, out = self.run_main(self.write("s.jsonl", lines))
        section = section_of(out, "## 4.", "## 5.")
        self.assertIn("Соединений с dial: 2; `dial_ms`: p50 300, p95 300, max 300 (замер есть у 1)", section)
        self.assertIn("`dial_timeout`: 1 (bob: 1)", section)
        only = [lines[1]]
        _, out = self.run_main(self.write("t.jsonl", only))
        self.assertIn("ни у одного нет `dial_ms`", out)
        self.assertNotIn("p50", out)

    def test_without_the_destination_the_table_says_why(self):
        lines = [conn_end(at(1), "c1", dial_ms=2000, dst_net=None, dst_port=None)]
        lines = [re.sub(r', "dst_net": null, "dst_port": null', "", x) for x in lines]
        _, out = self.run_main(self.write("s.jsonl", lines))
        self.assertIn("`SESSION_LOG_DST=none`", out)

    def test_a_journal_without_dials_says_so(self):
        _, out = self.run_main(self.write("s.jsonl", [assoc_end(at(1), "a1")]))
        self.assertIn("нет строк с dial", out)


class TopList(unittest.TestCase):
    def test_it_keeps_the_largest_and_the_earlier_of_equals_and_counts_all(self):
        top = jr.Top(3)
        for key, item in ((5, "a"), (1, "b"), (9, "c"), (5, "d"), (7, "e"), (5, "f")):
            top.add(key, item)
        self.assertEqual(top.items(), ["c", "e", "a"])
        self.assertEqual(top.count, 6)
        self.assertLessEqual(len(top.heap), 3)

    def test_of_equals_the_earlier_time_wins_whatever_the_reading_order(self):
        top = jr.Top(2)
        for key, item, when in ((5, "late", 30.0), (5, "early", 10.0), (5, "middle", 20.0), (9, "high", 40.0)):
            top.add(key, item, when)
        self.assertEqual(top.items(), ["high", "early"])

    def test_an_empty_list_and_a_zero_size_list_do_not_fail(self):
        self.assertEqual(jr.Top(3).items(), [])
        zero = jr.Top(0)
        zero.add(1, {})
        self.assertEqual((zero.items(), zero.count), ([], 1))

    def test_items_are_never_compared(self):
        top = jr.Top(2)
        for _ in range(5):
            top.add(1, {"a": 1})
        self.assertEqual(len(top.items()), 2)


class SlowOrder(Files):
    def test_equal_dials_keep_the_earlier_line_whichever_file_came_first(self):
        j = jr.Journal(options("--top", "1", "--slow-dial-ms", "100"))
        j.feed(conn_end(at(10), "late", dial_ms=900))
        j.feed(conn_end(at(1), "early", dial_ms=900))
        self.assertEqual([t for t, _, _ in j.slow.items()], [at(1)])

    def test_equal_long_streams_and_equal_native_losses_keep_the_earlier_line_too(self):
        j = jr.Journal(options("--top", "1", "--long-s", "1"))
        j.feed(conn_end(at(10), "late", dur_ms=5000))
        j.feed(conn_end(at(1), "early", dur_ms=5000))
        j.feed(assoc_end(at(10), "late", path_moves=1))
        j.feed(assoc_end(at(1), "early", path_moves=1))
        self.assertEqual([t for t, _, _ in j.long.items()], [at(1)])
        self.assertEqual([x[0] for x in j.flagged.items()], [at(1)])

    def test_equal_client_timeouts_keep_the_same_line_whichever_file_came_first(self):
        stamp_at = at(5)
        journal = [conn_end(at(4), "bb1", end="server_timeout"), conn_end(at(4), "aa1", end="server_timeout")]
        client = [line("TCP Tunnel closed", stamp_at, conn=c, closed_by="timeout", dur_ms=1) for c in ("aa1", "bb1")]
        client_log = self.write("c.log", client)
        shown = []
        for order in (journal, journal[::-1]):
            _, out = self.run_main(self.write("s.jsonl", order), "--client-log", client_log, "--top", "1")
            section = section_of(out, "### Соединения с closed_by=timeout", "## 8.")
            shown.append(re.findall(r"\| (aa1|bb1) \|", section))
        self.assertEqual(shown[0], shown[1])
        self.assertEqual(len(shown[0]), 1)

    def test_a_port_that_is_missing_beside_one_that_is_there_does_not_stop_the_report(self):
        lines = [conn_end(at(1), "c1", dial_ms=900, dst_port=443), conn_end(at(2), "c2", dial_ms=900, dst_port=None),
                 conn_end(at(3), "c3", dial_ms=900, dst_port="443", dst_net="203.0.113.0/24"),
                 conn_end(at(4), "c4", dial_ms=900, dst_port=-5, dst_net="203.0.113.0/24")]
        rc, out = self.run_main(self.write("s.jsonl", lines))
        self.assertEqual(rc, 0)
        section = section_of(out, "### Назначения по сети и порту", "## 5.")
        for want in ("198.51.100.0/24:443", "198.51.100.0/24:-", "203.0.113.0/24:-"):
            self.assertIn(want, section)


class Long(Files):
    def test_the_journal_does_not_keep_every_slow_or_long_line(self):
        j = jr.Journal(options("--top", "5", "--long-s", "1"))
        for i in range(500):
            j.feed(conn_end(at(i % 50), f"c{i}", dur_ms=2000 + i, dial_ms=900 + i))
            j.feed(assoc_end(at(i % 50), f"a{i}", path_moves=1))
        self.assertEqual((j.long.count, j.slow.count, j.flagged.count), (500, 500, 500))
        self.assertEqual((len(j.long.heap), len(j.slow.heap), len(j.flagged.heap)), (5, 5, 5))
        self.assertEqual(jr.num(j.long.items()[0][1], "dur_ms"), 2499)

    def test_streams_over_the_threshold_are_listed_longest_first(self):
        lines = [conn_end(at(1), "c1", dur_ms=2_000_000), conn_end(at(2), "c2", dur_ms=100_000, account="bob"),
                 conn_end(at(3), "c3", dur_ms=7_200_000, end="server_timeout"), assoc_end(at(4), "a1", dur_ms=9_000_000)]
        _, out = self.run_main(self.write("s.jsonl", lines))
        section = out[out.index("## 5."):out.index("## 6.")]
        self.assertIn("длиннее 1800 с: 2; `end`: client=1 server_timeout=1", section)
        self.assertLess(section.index("2:00:00"), section.index("0:33:20"))
        self.assertNotIn("0:01:40", section)
        _, out = self.run_main(self.write("t.jsonl", lines), "--long-s", "60", "--top", "1")
        section = out[out.index("## 5."):out.index("## 6.")]
        self.assertIn("длиннее 60 с: 3", section)
        self.assertEqual(section.count("| 2026-10-01"), 1)


class Udp(Files):
    def lines(self):
        return [
            assoc_end(at(1), "a1"),
            assoc_end(at(2), "a2", path_moves=2, native_up=30, native_down=40),
            assoc_end(at(3), "a3", native_up=10, native_down=10),
            assoc_end(at(4), "a4", dgram_up=5, dgram_down=5, native_up=0, native_down=0),
            assoc_end(at(5), "a5", tunnel_drops=3, account="bob"),
            assoc_end(at(6), "a6", cmd="tunnel", rotations=3, answered=True, end="timeout"),
            assoc_end(at(7), "a7", cmd="tunnel", rotations=6, answered=False),
        ]

    def test_an_association_that_did_not_hold_native_has_its_reasons(self):
        j = analyze(self.lines())
        ds = [json.loads(raw) for raw in self.lines()]
        reasons = {d["conn"]: jr.native_state(d, 0.8)[0] for d in ds if d["cmd"] == "native"}
        self.assertEqual(reasons, {"a1": [], "a2": ["path_moves", "low_native"], "a3": ["low_native"], "a4": [],
                                   "a5": ["tunnel_drops"]})
        self.assertEqual(jr.native_state({"dgram_up": 100, "dgram_down": 100, "native_up": 100, "native_down": 60}, 0.8)[0],
                         [])
        self.assertEqual(sorted(text(d, "conn") for _, d, _, _, _ in j.flagged.items()), ["a2", "a3", "a5"])

    def test_the_report_summarises_the_kinds_and_lists_the_flagged_first(self):
        _, out = self.run_main(self.write("s.jsonl", self.lines()))
        section = out[out.index("## 6."):out.index("## 8.")]
        self.assertIn("Ассоциаций native: 5", section)
        self.assertIn("Не удержали native: 3", section)
        self.assertIn("`path_moves` всего 2 (ассоциаций с переходом ответов на поток: 1)", section)
        self.assertRegex(section, r"\| tunnel \| 2 \| client=1 timeout=1 \| .* \| 2 \(ответ был: 1\) \|")
        self.assertLess(section.index("path_moves, low_native"), section.index("| 3 | tunnel_drops |"))
        self.assertNotIn("a1", section)

    def test_no_associations_and_no_native_are_said_plainly(self):
        _, out = self.run_main(self.write("s.jsonl", [conn_end(at(1), "c1")]))
        self.assertIn("В журнале нет `assoc_end`.", out)
        _, out = self.run_main(self.write("t.jsonl", [assoc_end(at(1), "a1", cmd="tunnel")]))
        self.assertIn("Ассоциаций `cmd=native` нет.", out)


class ClientJoin(Files):
    SECRET = "192.0.2.7:5555"

    def journal(self):
        return [
            conn_end(at(1), "c1", end="client"),
            conn_end(at(2), "c2", end="target"),
            conn_end(at(3), "c3", end="server_timeout", dur_ms=45000),
            conn_end(at(4), "c4", end="reset", account="bob"),
            conn_end(at(5), "c5", end="client"),
        ]

    def client(self):
        def tcp(t, conn, by, **f):
            return line("TCP Tunnel closed", t, conn=conn, dest="example.test", server=self.SECRET, transport="obfs",
                        setup_ms=50, dur_ms=f.pop("dur_ms", 4000), up=10, down=20, closed_by=by,
                        error=f"read tcp {self.SECRET}: i/o timeout", **f)
        return [
            tcp(at(1, 1), "c1", "app"), tcp(at(2, 1), "c2", "server"), tcp(at(3, 1), "c3", "timeout", dur_ms=44000),
            tcp(at(4, 1), "c4", "app"), tcp(at(9), "zz", "app"), tcp(at(9), "ya", "timeout"),
            line("UDP Tunnel closed", at(6), conn="c5", closed_by="application"),
            line("Minute summary", at(7)), "not json at all",
        ]

    def test_lines_are_matched_by_conn_and_the_two_reasons_compared(self):
        cl = jr.ClientLog([self.write("client.log", self.client())])
        self.assertEqual((cl.tcp, len(cl.conns), cl.lines), (6, 6, 8))
        j = jr.Journal(options(), cl)
        for raw in self.journal():
            j.feed(raw)
        self.assertEqual(j.matched, {"c1", "c2", "c3", "c4"})
        self.assertEqual(dict(j.pairs), {("app", "client"): 1, ("server", "target"): 1,
                                          ("timeout", "server_timeout"): 1, ("app", "reset"): 1})
        self.assertEqual([(c, a, e) for _, c, a, e, _, _ in j.client_timeouts.items()], [("c3", "alice", "server_timeout")])

    def test_the_report_shows_the_disagreement_first_and_leaks_nothing_of_the_client_log(self):
        client = self.write("client.log", self.client())
        rc, out = self.run_main(self.write("s.jsonl", self.journal()), "--client-log", client)
        self.assertEqual(rc, 0)
        section = out[out.index("## 7."):out.index("## 8.")]
        self.assertIn("`TCP Tunnel closed`: 6", section)
        self.assertIn("Найдено среди `conn_end` по `conn`: 4 (66.7%)", section)
        self.assertLess(section.index("| app | reset | 1 | возможно |"), section.index("| app | client | 1 | ожидаемо |"))
        self.assertIn("closed_by=timeout у клиента: 2, найдено в журнале 1", section)
        self.assertIn("| c3 | alice | server_timeout | 0:00:45 | 0:00:44 |", section)
        for secret in (self.SECRET, "example.test", "i/o timeout", "192.0.2."):
            self.assertNotIn(secret, out)

    def test_the_judge_table_over_every_pair(self):
        setup = ["rules_denied", "private_dest", "resolve_failed", "dial_timeout", "dial_refused", "dial_unreachable"]
        by_client = ["app", "server", "tunnel_error", "timeout", "weird", "(нет)"]
        by_server = ["client", "target", "server_timeout", "account", "shutdown", "reset", "error", "?"] + setup
        want = {(by, end): jr.POSSIBLE for by in by_client for end in by_server}
        want["app", "client"] = jr.EXPECTED
        for end in ("target", "server_timeout", "account", "shutdown", "reset", *setup):
            want["server", end] = jr.EXPECTED
        for end in ("reset", "server_timeout", "account", "shutdown"):
            want["tunnel_error", end] = jr.EXPECTED
        for end in ("server_timeout", "reset"):
            want["timeout", end] = jr.EXPECTED
        for by in ("app", "tunnel_error", "timeout"):
            for end in setup:
                want[by, end] = jr.CONTRADICTION
        for pair, verdict in want.items():
            self.assertEqual(jr.judge(*pair), verdict, pair)
        self.assertEqual(sorted(p for p, v in want.items() if v == jr.CONTRADICTION),
                         sorted((by, end) for by in ("app", "tunnel_error", "timeout") for end in setup))
        self.assertEqual((jr.EXPECTED, jr.POSSIBLE, jr.CONTRADICTION), ("ожидаемо", "возможно", "противоречие"))

    def test_a_refused_connect_of_the_client_agrees_with_the_setup_failure_of_the_server(self):
        journal = [conn_end(at(1), "c1", end="dial_timeout", result="dial_timeout"),
                   conn_end(at(2), "c2", end="dial_timeout", result="dial_timeout")]
        client = [line("TCP Tunnel closed", at(1, 1), conn="c1", closed_by="server", reply=4, dur_ms=0),
                  line("TCP Tunnel closed", at(2, 1), conn="c2", closed_by="app", dur_ms=1)]
        _, out = self.run_main(self.write("s.jsonl", journal), "--client-log", self.write("c.log", client))
        section = section_of(out, "## 7.", "## 8.")
        self.assertIn("| server | dial_timeout | 1 | ожидаемо |", section)
        self.assertIn("| app | dial_timeout | 1 | противоречие |", section)

    def test_the_report_orders_the_verdicts_and_explains_them_from_the_same_table(self):
        journal = [conn_end(at(1), "c1", end="dial_timeout", result="dial_timeout"),
                   conn_end(at(2), "c2", end="reset"), conn_end(at(3), "c3", end="client")]
        client = [line("TCP Tunnel closed", at(1, 1), conn="c1", closed_by="app", dur_ms=1),
                  line("TCP Tunnel closed", at(2, 1), conn="c2", closed_by="app", dur_ms=1),
                  line("TCP Tunnel closed", at(3, 1), conn="c3", closed_by="app", dur_ms=1)]
        _, out = self.run_main(self.write("s.jsonl", journal), "--client-log", self.write("c.log", client))
        section = section_of(out, "## 7.", "## 8.")
        rows = ["| app | dial_timeout | 1 | противоречие |", "| app | reset | 1 | возможно |",
                "| app | client | 1 | ожидаемо |"]
        self.assertEqual([section.index(r) for r in rows], sorted(section.index(r) for r in rows))
        for r in rows:
            self.assertIn(r, section)
        self.assertIn("- `server`: ожидаемо - target, server_timeout, account, shutdown, reset, rules_denied, "
                      "private_dest, resolve_failed, dial_timeout, dial_refused, dial_unreachable; "
                      "прочие end - возможно.", section)
        for text_line in jr.agreement_lines():
            self.assertIn(text_line, section)
        self.assertEqual(len(jr.agreement_lines()), len(jr.AGREEMENT))
        self.assertNotIn("согласуется", out)

    def test_both_sides_closing_first_is_a_race_not_a_contradiction(self):
        self.assertEqual(jr.judge("server", "client"), jr.POSSIBLE)

    def test_the_client_timeouts_kept_are_the_latest_ones(self):
        client = [line("TCP Tunnel closed", at(i), conn=f"c{i}", closed_by="timeout", dur_ms=i) for i in (1, 2, 3, 4)]
        journal = [conn_end(at(i), f"c{i}", end="server_timeout") for i in (1, 2, 3, 4)]
        cl = jr.ClientLog([self.write("c.log", client)])
        j = jr.Journal(options("--top", "2"), cl)
        for raw in journal:
            j.feed(raw)
        self.assertEqual([c for _, c, _, _, _, _ in j.client_timeouts.items()], ["c4", "c3"])
        self.assertEqual(j.client_timeouts.count, 4)
        _, out = self.run_main(self.write("s.jsonl", journal), "--client-log", self.write("d.log", client), "--top", "2")
        self.assertIn("closed_by=timeout у клиента: 4, найдено в журнале 4 (показаны самые поздние, 2)", out)

    def test_a_non_numeric_duration_in_the_client_log_is_counted(self):
        client = [line("TCP Tunnel closed", at(1), conn="c1", closed_by="app", dur_ms="long", up=True)]
        cl = jr.ClientLog([self.write("c.log", client)])
        self.assertEqual(dict(cl.bad), {"dur_ms": 1, "up": 1})
        _, out = self.run_main(self.write("s.jsonl", [conn_end(at(1), "c1")]), "--client-log", self.write("d.log", client))
        self.assertIn("| dur_ms | 1 |", section_of(out, "### Числовые поля"))

    def test_without_the_client_log_the_section_says_so(self):
        _, out = self.run_main(self.write("s.jsonl", self.journal()))
        self.assertIn("Лог клиента не передан", out)

    def test_several_client_files_and_an_unreadable_one(self):
        a = self.write("a.log", self.client()[:2])
        b = self.write("archive-1.log.gz", self.client()[2:4], gz=True)
        cl = jr.ClientLog([a, b])
        self.assertEqual(len(cl.conns), 4)
        rc, out = self.run_main(self.write("s.jsonl", self.journal()), "--client-log", os.path.join(self.dir, "none.log"))
        self.assertEqual(rc, 1)
        self.assertIn("FileNotFoundError", out)


class BadNumbers(Files):
    def test_a_numeric_field_of_another_type_is_counted_and_read_as_absent(self):
        lines = [
            conn_end(at(1), "c1", dur_ms="5000", up=True, down=None),
            conn_end(at(2), "c2", dur_ms=float("nan"), dial_ms="100"),
            conn_end(at(3), "c3", up=10 ** 30),
            conn_end(at(4), "c4"),
        ]
        j = analyze(lines)
        self.assertEqual(dict(j.bad), {"dur_ms": 2, "up": 2, "down": 1, "dial_ms": 1})
        self.assertEqual((j.dial_n, j.dials), (4, [120, 120, 120]))
        _, out = self.run_main(self.write("s.jsonl", lines))
        section = section_of(out, "### Числовые поля с нечисловым значением", "### Поля вне")
        for row in ("| dur_ms | 2 |", "| up | 2 |", "| down | 1 |", "| dial_ms | 1 |"):
            self.assertIn(row, section)

    def test_a_clean_journal_reports_no_bad_numbers(self):
        self.assertEqual(dict(analyze([conn_end(at(1), "c1"), assoc_end(at(2), "a1")]).bad), {})

    def test_num_does_not_turn_a_string_or_a_bool_into_a_number(self):
        for v in ("12", True, None, [1], float("inf"), 10 ** 30):
            self.assertEqual(jr.num({"x": v}, "x"), 0, v)
            self.assertIsNone(jr.num({"x": v}, "x", None), v)
        self.assertEqual(jr.num({"x": 7}, "x"), 7)
        self.assertEqual(jr.num({"x": 7.5}, "x"), 7.5)


class Cli(Files):
    def test_the_script_runs_as_a_program_and_prints_help(self):
        out = subprocess.run([sys.executable, SCRIPT, "--help"], capture_output=True, text=True, check=True).stdout
        for flag in ("--client-log", "--service-log", "--slow-dial-ms", "--long-s"):
            self.assertIn(flag, out)
        path = self.write("s.jsonl", [conn_end(at(1), "c1")])
        res = subprocess.run([sys.executable, SCRIPT, path], capture_output=True, check=True,
                             env=dict(os.environ, PYTHONIOENCODING="ascii", LC_ALL="C"))
        self.assertIn("# Отчет по журналу сессий S5Core", res.stdout.decode("utf-8"))

    def test_a_top_or_a_cluster_size_below_one_is_refused(self):
        for flag in ("--top", "--cluster-accounts"):
            for value in ("0", "-3", "x"):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                    options(flag, value)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(flag, err.getvalue())
        self.assertEqual(options("--top", "1").top, 1)
        self.assertEqual(options("--cluster-accounts", "3").cluster_accounts, 3)

    def test_a_share_outside_zero_to_one_or_a_negative_threshold_is_refused(self):
        for flag, value in (("--native-share", "5"), ("--native-share", "-0.1"), ("--native-share", "nan"),
                            ("--slow-dial-ms", "-1"), ("--long-s", "-1")):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as raised:
                options(flag, value)
            self.assertEqual(raised.exception.code, 2, (flag, value))
        self.assertEqual(options("--native-share", "1").native_share, 1.0)
        self.assertEqual(options("--slow-dial-ms", "0").slow_dial_ms, 0)

    def test_a_value_that_is_not_a_number_is_named_in_the_refusal(self):
        for flag in ("--top", "--slow-dial-ms", "--native-share"):
            err = io.StringIO()
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
                options(flag, "abc")
            self.assertIn("получено 'abc'", err.getvalue())
            self.assertNotIn("invalid", err.getvalue())

    def test_a_client_log_given_twice_counts_once(self):
        client = self.write("c.log", [line("TCP Tunnel closed", at(1, 1), conn="c1", closed_by="app", dur_ms=1)])
        journal = self.write("s.jsonl", [conn_end(at(1), "c1")])
        _, out = self.run_main(journal, "--client-log", client, "--client-log", client)
        self.assertIn("Строк лога клиента: 1;", out)

    def test_the_report_has_no_banned_characters(self):
        lines = [conn_end(at(1), "c1", end="server_timeout"), assoc_end(at(2), "a1")]
        _, out = self.run_main(self.write("s.jsonl", lines))
        banned = "\u0451\u0401\u2014\u00ab\u00bb\u20bd"
        for ch in banned:
            self.assertNotIn(ch, out)
        for path in (SCRIPT, __file__):
            with open(path, encoding="utf-8") as f:
                source = f.read()
            for ch in banned:
                self.assertNotIn(ch, source)


if __name__ == "__main__":
    unittest.main()
