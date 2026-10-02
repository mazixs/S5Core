import json
import os
import random
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pipeline import analysis, cell, plan, report  # noqa: E402
from pipeline.util import cpu_list, go_duration, seconds  # noqa: E402

PLANS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plans")


def raw_plan(**over):
    p = {
        "name": "t", "base": "a", "candidate": "b",
        "variants": {"raw": {"direct": True}, "a": {"ref": "HEAD"}, "b": {"ref": "worktree"}},
        "cpus": {"raw": "0", "obfs": ["1", "2"], "wss": ["3", "4"]},
        "series": [{"name": "lo", "rounds": 2}],
    }
    p.update(over)
    return p


def native_plan(**over):
    native = {"server": {"UDP_PORT": "41443"}, "client": {"UDP_NATIVE": "true"}}
    return raw_plan(base="n", candidate="n", cpus={"raw": "0", "plain": ["5"], "obfs": ["1", "2"], "wss": ["3", "4"]}, variants={
        "raw": {"direct": True}, "tcp": {"ref": "HEAD"}, "n": {"ref": "worktree", "env": native},
        "off": {"ref": "worktree", "env": {"server": native["server"]}},
        "zero": {"ref": "worktree", "env": {"server": {"UDP_PORT": "0"}, "client": native["client"]}},
    }, **over)


class Units(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(seconds("5m"), 300)
        self.assertEqual(seconds("2h"), 7200)
        self.assertEqual(seconds("250ms"), 0.25)
        self.assertEqual(seconds(7), 7)
        self.assertEqual(go_duration(90), "90s")
        self.assertEqual(go_duration(0.25), "250ms")
        with self.assertRaises(ValueError):
            seconds("5 minutes")

    def test_cpu_list(self):
        self.assertEqual(cpu_list("0-2,8"), {0, 1, 2, 8})


class Verdict(unittest.TestCase):
    def test_same_sign_and_big_is_a_verdict(self):
        r = analysis.verdict("ms", -1, [(10, 12), (10, 11), (10, 13)], 3)
        self.assertEqual(r["verdict"], "хуже")
        r = analysis.verdict("MB/s", 1, [(10, 12), (10, 11), (10, 13)], 3)
        self.assertEqual(r["verdict"], "лучше")

    def test_one_round_against_is_no_verdict(self):
        r = analysis.verdict("ms", -1, [(10, 12), (10, 11), (10, 9)], 3)
        self.assertEqual(r["verdict"], "нет")
        self.assertEqual((r["worse"], r["better"]), (2, 1))

    def test_small_change_is_no_verdict(self):
        r = analysis.verdict("ms", -1, [(100, 101), (100, 102), (100, 103)], 3)
        self.assertEqual(r["verdict"], "нет")

    def test_milliseconds_need_an_absolute_floor(self):
        r = analysis.verdict("ms", -1, [(0.1, 0.11), (0.1, 0.112), (0.1, 0.115)], 3)
        self.assertEqual(r["verdict"], "нет")

    def test_percent_uses_points(self):
        self.assertEqual(analysis.verdict("%", -1, [(0, 0.6), (0, 0.7), (0, 0.8)], 3)["verdict"], "хуже")
        self.assertEqual(analysis.verdict("%", -1, [(0, 0.3), (0, 0.4), (0, 0.2)], 3)["verdict"], "нет")

    def test_too_few_pairs(self):
        self.assertEqual(analysis.verdict("ms", -1, [(10, 20), (10, 20)], 3)["verdict"], "мало пар")

    def test_sign_p(self):
        self.assertEqual(analysis.sign_p(0, 0), 1.0)
        self.assertAlmostEqual(analysis.sign_p(3, 0), 0.25)
        self.assertAlmostEqual(analysis.sign_p(5, 0), 2 / 32)
        self.assertAlmostEqual(analysis.sign_p(2, 1), 1.0)

    def test_binom_p(self):
        self.assertEqual(analysis.binom_p(0, 100, 0, 100), 1.0)
        self.assertGreater(analysis.binom_p(5, 1000, 6, 1000), 0.5)
        self.assertLess(analysis.binom_p(2, 1000, 30, 1000), 1e-5)
        self.assertAlmostEqual(analysis.binom_p(0, 100, 5, 100), 2 / 32)
        self.assertAlmostEqual(analysis.binom_p(1500, 4000, 1500, 4000), 1.0)
        self.assertLess(analysis.binom_p(1200, 4000, 1800, 4000), 1e-9)


class Plans(unittest.TestCase):
    def test_native_udp_metrics_keep_fixed_outcomes(self):
        gauges = cell.parse_gauges('s5core_native_udp_packets_total{outcome="accepted"} 42\n'
                                   's5core_native_udp_packets_total{outcome="replay"} 2\n'
                                   's5core_native_udp_sessions 3\n')
        self.assertEqual(gauges['native_udp_accepted'], 42)
        self.assertEqual(gauges['native_udp_replay'], 2)
        self.assertEqual(gauges['s5core_native_udp_sessions'], 3)

    def test_native_udp_paths_keep_one_key_per_label_set(self):
        g = cell.parse_gauges('s5core_native_udp_datagrams_total{direction="to_client",path="native"} 40\n'
                              's5core_native_udp_datagrams_total{direction="to_client",path="tcp_oversize"} 2\n'
                              's5core_native_udp_datagrams_total{direction="from_client",path="tcp_route"} 3\n'
                              's5core_native_udp_route_events_total{event="stale_loss"} 1\n'
                              's5core_native_udp_stream_drops_total{reason="age"} 5\n'
                              's5core_native_udp_stream_drops_total{otel_scope_name="a"} 7\n')
        self.assertEqual({k: v for k, v in g.items() if k.startswith("native_udp_")},
                         {"native_udp_to_client_native": 40, "native_udp_to_client_tcp_oversize": 2,
                          "native_udp_from_client_tcp_route": 3, "native_udp_route_stale_loss": 1,
                          "native_udp_stream_drop_age": 5})

    def test_native_udp_outcomes_are_not_summed_into_a_volume(self):
        g = cell.parse_gauges('s5core_native_udp_packets_total{outcome="accepted",otel_scope_name="a"} 40\n'
                              's5core_native_udp_packets_total{outcome="accepted",otel_scope_name="b"} 2\n'
                              's5core_native_udp_packets_total{outcome="tag"} 1\n'
                              's5core_native_udp_packets_total{outcome="replay"} 2\n'
                              's5core_native_udp_packets_total{outcome="auth"} 3\n'
                              's5core_native_udp_packets_total{outcome="read_error"} 4\n')
        self.assertNotIn("s5core_native_udp_packets_total", g)
        self.assertEqual({k: v for k, v in g.items() if k.startswith("native_udp_")},
                         {"native_udp_accepted": 42, "native_udp_tag": 1, "native_udp_replay": 2, "native_udp_auth": 3,
                          "native_udp_read_error": 4, "native_udp_dropped": 6})
        self.assertEqual(cell.parse_gauges('s5core_native_udp_packets_total{outcome="accepted"} 5\n')["native_udp_dropped"], 0)

    def test_udp_blackout_targets_only_native_port(self):
        cmds = []
        blackout = cell.UDPBlackout("41443", 0, 0.001)
        with patch.object(cell, "_sh", side_effect=lambda cmd: cmds.append(cmd)):
            blackout.start()
            blackout.join(timeout=1)
        self.assertFalse(blackout.is_alive())
        self.assertTrue(blackout.started_at)
        adds = [c for c in cmds if c[:3] == ["tc", "filter", "add"]]
        self.assertEqual(len(adds), 2)
        self.assertTrue(all("17" in c and "41443" in c and "drop" in c for c in adds))
        self.assertTrue(all("6" not in c for c in adds))
        self.assertEqual(cmds[-1][:3], ["tc", "filter", "del"])

    def test_udp_blackout_plan_needs_both_times(self):
        def resolve(**net):
            return plan.resolve(native_plan(series=[{"name": "n", "network": {"rtt_ms": 50, **net}, "variants": ["n"]}]), ".")
        for bad in ({"udp_blackout_after_s": 0}, {"udp_blackout_for_s": 1},
                    {"udp_blackout_after_s": -1, "udp_blackout_for_s": 1},
                    {"udp_blackout_after_s": 0, "udp_blackout_for_s": 0}):
            with self.assertRaises(plan.PlanError):
                resolve(**bad)
        resolve(udp_blackout_after_s=1, udp_blackout_for_s=2)

    def test_udp_blackout_is_refused_before_the_run_where_it_has_no_native_leg(self):
        blackout = {"rtt_ms": 50, "udp_blackout_after_s": 10, "udp_blackout_for_s": 12}

        def resolve(**series):
            return plan.resolve(native_plan(series=[{"name": "bm", "network": blackout, **series}]), ".")
        bad = {
            "raw": {"variants": ["raw", "n"]},
            "tcp": {"variants": ["tcp", "n"]},
            "plain": {"variants": ["n"], "transports": ["plain"], "auth": "none"},
            "off": {"variants": ["off"]},
            "zero": {"variants": ["zero"]},
        }
        for variant, series in bad.items():
            with self.assertRaises(plan.PlanError, msg=variant) as e:
                resolve(**series)
            self.assertIn("blackout", str(e.exception))
            self.assertIn(variant, str(e.exception))
        with self.assertRaises(plan.PlanError):
            resolve(variants=["raw", "n"], group="g")
        cells = [c for b in plan.expand(resolve(variants=["n"])) for c in b["cells"]]
        self.assertEqual({c["transport"] for c in cells}, {"obfs", "wss"})
        # UDP_PORT from the series env counts as the variant's, as it does in the cell.
        resolve(variants=["tcp"], env={"server": {"UDP_PORT": "41443"}, "client": {"UDP_NATIVE": "true"}})

    def test_the_cell_refuses_a_blackout_before_it_shapes_lo(self):
        written = {}
        with tempfile.TemporaryDirectory() as d:
            spec = {"id": "bm/raw-r1", "dir": d, "tmp": d, "parent_pid": os.getppid(), "parent_netns": -1,
                    "network": {"rtt_ms": 50, "udp_blackout_after_s": 0, "udp_blackout_for_s": 1},
                    "direct": True, "transport": "direct", "shape": "all", "env": {"server": {}, "client": {}}}
            with patch.object(cell, "read_json", return_value=spec), patch.object(cell, "set_pdeathsig"), \
                    patch.object(cell.signal, "signal"), patch.object(cell, "netns_inode", return_value=1), \
                    patch.object(cell, "netem") as shaped, patch.object(cell, "_sh", return_value=""), \
                    patch.object(cell, "write_json", side_effect=lambda path, run: written.update(run)):
                with self.assertRaises(SystemExit):
                    cell.main("spec.json")
        shaped.assert_not_called()
        self.assertEqual(written["status"], "setup_failed")
        self.assertIn("blackout", written["reason"])

    def test_native_udp_is_shaped_with_its_tcp_control_leg(self):
        commands = []
        spec = {"network": {"rtt_ms": 50, "loss_pct": 0.5, "rate_mbit": 0},
                "shape": 41444, "env": {"server": {"UDP_PORT": "41443"}}}
        with patch.object(cell, "_sh", side_effect=lambda command: commands.append(command)):
            cell.netem(spec)
        filters = [c for c in commands if c[:3] == ["tc", "filter", "add"]]
        self.assertEqual(len(filters), 4)
        def matched(proto, port):
            return any(any(c[i:i+5] == ["match", "ip", "protocol", proto, "0xff"] for i in range(len(c)-4))
                       and port in c for c in filters)
        self.assertTrue(matched("6", "41444"))
        self.assertTrue(matched("17", "41443"))

    def test_an_uplink_queues_only_the_upstream_direction(self):
        def net(**kw):
            return plan.resolve(raw_plan(series=[{"name": "n", "network": {"rtt_ms": 50, **kw}}]), ".")["series"][0]["network"]
        for bad in ({"uplink_mbit": 3}, {"queue_kb": 256}, {"uplink_mbit": 3, "queue_kb": 256, "queue": "red"},
                    {"uplink_mbit": 3, "queue_kb": 256, "rate_mbit": 10}, {"uplink_mbit": 3, "queue_kb": 0}):
            with self.assertRaises(plan.PlanError):
                net(**bad)
        self.assertEqual(net(uplink_mbit=3, queue_kb=256)["queue"], "fifo")
        n = net(uplink_mbit=3, queue_kb=256, queue="fq_codel")
        self.assertIn("аплинк 3 Мбит/с, очередь fq_codel 256 КБ", report.net_title(n))
        for shape, udp, up in ((41443, "41443", [["dport", "41443", "6"], ["dport", "41443", "17"]]),
                               ("all", None, [["src", "127.0.0.2/32"]])):
            commands = []
            spec = {"network": n, "shape": shape, "env": {"server": {"UDP_PORT": udp} if udp else {}}, "settings": {}}
            with patch.object(cell, "_sh", side_effect=lambda command: commands.append(command)):
                self.assertIsNone(cell.netem(spec))
            self.assertIn(["ethtool", "-K", "lo", "gso", "off", "gro", "off", "tso", "off"], commands)
            qdiscs = [c[5:] for c in commands if c[:4] == ["tc", "qdisc", "add", "dev"]]
            self.assertEqual([q[:4] for q in qdiscs[1:]], [["parent", "1:2", "handle", "20:"], ["parent", "1:3", "handle", "30:"],
                                                         ["parent", "30:1", "handle", "40:"], ["parent", "40:1", "handle", "41:"]])
            self.assertEqual(qdiscs[3][4:10], ["tbf", "rate", "3mbit", "burst", "3028", "limit"])
            self.assertEqual(qdiscs[4][-2:], ["memory_limit", str(256 * 1024)])
            to_up = [c for c in commands if c[:3] == ["tc", "filter", "add"] and c[-1] == "1:3"]
            self.assertEqual(len(to_up), len(up))
            for c, want in zip(to_up, up):
                self.assertTrue(all(w in c for w in want), c)
        # The direct cell binds to the same address, or the queue would not see its upstream.
        spec = {"network": n, "shape": "all", "direct": True, "id": "x", "bin": {"matrix": "m"},
                "settings": {"scenario_timeout": "1m", "hang_grace": "5s", "max_errors_in_row": 5}}
        a = cell._gen_args(spec, "")
        self.assertEqual(a[a.index("-source") + 1], plan.CLIENT_IP)

    def test_a_wake_delays_the_leg_only_while_the_generator_holds_it(self):
        def net(**kw):
            return plan.resolve(raw_plan(series=[{"name": "n", "network": {"rtt_ms": 50, **kw}}]), ".")["series"][0]["network"]
        for bad in ({"wake_delay_ms": 0}, {"wake_delay_ms": 260, "uplink_mbit": 3, "queue_kb": 256}):
            with self.assertRaises(plan.PlanError):
                net(**bad)
        n = net(wake_delay_ms=260)
        # The rate keeps the order: what is sent after the hold waits behind what was delayed.
        self.assertEqual(cell.netem_args(n), ["netem", "delay", "25ms", "loss", "0%", "rate", "10gbit", "limit", "100000"])
        self.assertEqual(cell.netem_args(n, wake=True)[:3], ["netem", "delay", "285ms"])
        base = {"network": n, "id": "x", "bin": {"matrix": "m"}, "settings": {"scenario_timeout": "1m", "hang_grace": "5s", "max_errors_in_row": 5}}
        for shape, socks, target in (("all", "", ["root", "handle", "1:"]), (41443, "127.0.0.1:41081", ["parent", "1:3", "handle", "30:"])):
            a = cell._gen_args(base | {"shape": shape}, socks)
            on, off = (json.loads(a[a.index(f) + 1]) for f in ("-wake-on", "-wake-off"))
            self.assertEqual(on[:5 + len(target)], ["tc", "qdisc", "change", "dev", "lo", *target])
            self.assertIn("285ms", on)
            self.assertEqual(off[5 + len(target):], cell.netem_args(n))

    def test_windows_count_what_follows_a_mark(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "gauges.jsonl"), "w") as f:
                for t, v in ((99.9, 5), (100.5, 7), (101.4, 9), (106, 9)):
                    f.write(json.dumps({"t": t, "native_udp_from_client_tcp_route": v}) + "\n")
            with open(os.path.join(d, "leg.jsonl"), "w") as f:
                f.write(json.dumps({"t": 100.2, "t40000": [3, 900, 0, 0], "t40001": [1, 60, 1, 60], "udp": [2, 400, 1, 200]}) + "\n")
                f.write(json.dumps({"t": 105.5, "t40001": [1, 60, 0, 0]}) + "\n")
            w = cell.windows({"network": {"rtt_ms": 50, "wake_delay_ms": 260}}, d, {"resume_at": [100.0]})["resume"][0]
        self.assertAlmostEqual(w["span_s"], 1.385)
        self.assertEqual(w["server"], {"native_udp_from_client_tcp_route": 2})
        self.assertEqual((w["leg"]["tcp_up_packets"], w["leg"]["tcp_up_busiest"], w["leg"]["udp_up_packets"]), (4, 3, 2))
        self.assertEqual(w["leg_steady"]["tcp_up_packets"], 1)

    def test_the_client_log_gives_path_moves_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "client.log")
            with open(path, "w") as f:
                f.write('{"time":"2026-09-26T10:00:01.123456789+02:00","level":"WARN","msg":"Native UDP path lost; association using 0x83","unanswered_probes":3}\n')
                f.write('{"time":"2026-09-26T10:00:02+02:00","level":"INFO","msg":"UDP Tunnel closed","reason":"x","native_sent":10,"tcp_sent_other":2}\n')
                f.write('{"time":"2026-09-26T10:00:03+02:00","level":"INFO","msg":"UDP Tunnel closed","reason":"x","native_sent":5,"tcp_sent_other":1}\n')
            got = cell.native_log(path)
        self.assertEqual(got["events"], {"path_lost": 1})
        self.assertAlmostEqual(got["event_at"]["path_lost"][0] % 60, 1.123456, places=5)
        self.assertEqual(got["stats"], {"native_sent": 15, "tcp_sent_other": 3})

    def test_capture_disables_loopback_superpackets(self):
        commands = []
        spec = {"network": "loopback", "shape": None, "settings": {"capture": True}}
        with patch.object(cell, "_sh", side_effect=lambda command: commands.append(command)):
            cell.netem(spec)
        self.assertIn(["ip", "link", "set", "lo", "mtu", "1500"], commands)
        self.assertIn(["ethtool", "-K", "lo", "gso", "off", "gro", "off", "tso", "off"], commands)

    def test_shipped_plans_load(self):
        for name in os.listdir(PLANS):
            if name.endswith(".toml"):
                p = plan.load(os.path.join(PLANS, name))
                self.assertTrue(plan.expand(p), name)

    def test_unknown_keys_fail(self):
        with self.assertRaises(plan.PlanError):
            plan.resolve(raw_plan(extra=1), ".")
        with self.assertRaises(plan.PlanError):
            plan.resolve(raw_plan(series=[{"name": "lo", "round": 3}]), ".")
        with self.assertRaises(plan.PlanError):
            plan.resolve(raw_plan(defaults={"scenario_timeout": "soon"}), ".")

    def test_plain_needs_no_auth(self):
        with self.assertRaises(plan.PlanError):
            plan.resolve(raw_plan(series=[{"name": "lo", "transports": ["plain"]}]), ".")
        plan.resolve(raw_plan(series=[{"name": "lo", "transports": ["plain"], "auth": "none"}]), ".")

    def test_loopback_cells_alternate_order(self):
        b = plan.expand(plan.resolve(raw_plan(), "."))
        ids = [x["id"] for x in b]
        self.assertEqual(len(ids), 10)
        self.assertEqual(ids[0], "lo/raw-r1")
        self.assertEqual(ids[5], "lo/b-wss-member-r2")
        self.assertEqual(ids[-1], "lo/raw-r2")

    def test_netem_round_is_one_batch_on_disjoint_cpus(self):
        p = plan.resolve(raw_plan(series=[{"name": "n", "network": {"rtt_ms": 40}, "rounds": 2}]), ".")
        b = plan.expand(p)
        self.assertEqual([x["id"] for x in b], ["n/r1", "n/r2"])
        self.assertEqual(len(b[0]["cells"]), 5)
        for x in b:
            cpus = [c["cpus"] for c in x["cells"]]
            self.assertEqual(len(cpus), len(set(cpus)))
        self.assertEqual({c["shape"] for c in b[0]["cells"]}, {"all", 41443, 41444})

    def test_plain_under_netem_is_shaped_by_the_client_address(self):
        p = raw_plan(cpus={"raw": "0", "plain": ["1", "6"], "obfs": ["2", "3"], "wss": ["4", "5"]},
                     series=[{"name": "n", "network": {"rtt_ms": 40}, "transports": ["plain", "obfs"], "auth": "none"}])
        shapes = {c["transport"]: c["shape"] for c in plan.expand(plan.resolve(p, "."))[0]["cells"] if not c["direct"]}
        self.assertEqual(shapes, {"plain": plan.CLIENT_IP, "obfs": 41443})

    def test_loss_burst(self):
        def net(**kw):
            return plan.resolve(raw_plan(series=[{"name": "n", "network": {"rtt_ms": 40, **kw}}]), ".")["series"][0]["network"]
        self.assertNotIn("loss_burst", net(loss_pct=1))
        for bad in ({"loss_burst": 4}, {"loss_pct": 1, "loss_burst": 0.5}):
            with self.assertRaises(plan.PlanError):
                net(**bad)
        args = cell.netem_args(net(loss_pct=2, loss_burst=4))
        i = args.index("gemodel")
        p, r = (float(x.rstrip("%")) / 100 for x in args[i + 1:i + 3])
        self.assertAlmostEqual(p / (p + r), 0.02)
        self.assertAlmostEqual(1 / r, 4)
        self.assertEqual(cell.netem_args(net(loss_pct=0.5, rate_mbit=200)),
                         ["netem", "delay", "20ms", "loss", "0.5%", "rate", "200mbit", "limit", "100000"])

    def test_loss_outage(self):
        def net(**kw):
            return plan.resolve(raw_plan(series=[{"name": "n", "network": {"rtt_ms": 40, **kw}}]), ".")["series"][0]["network"]
        self.assertNotIn("loss_outage_ms", net(loss_pct=1))
        for bad in ({"loss_outage_ms": 30}, {"loss_pct": 1, "loss_outage_ms": 0}, {"loss_pct": 1, "loss_outage_ms": 30, "loss_burst": 4}):
            with self.assertRaises(plan.PlanError):
                net(**bad)
        n = net(loss_pct=2, loss_outage_ms=30)
        self.assertEqual(cell.netem_args(n), ["netem", "delay", "20ms", "loss", "0%", "limit", "100000"])
        self.assertEqual(cell.netem_args(n, out=True), ["netem", "delay", "20ms", "loss", "100%", "limit", "100000"])
        draws = [d for d, _ in zip(cell.spells(2, 30, random.Random(1)), range(20000))]
        up, out = (sum(x) / len(draws) for x in zip(*draws))
        self.assertAlmostEqual(out, 0.030, delta=0.001)
        self.assertAlmostEqual(out / (up + out), 0.02, delta=0.001)

    def test_delay_jitter_and_spikes_keep_the_packet_order(self):
        def net(**kw):
            return plan.resolve(raw_plan(series=[{"name": "n", "network": {"rtt_ms": 40, **kw}}]), ".")["series"][0]["network"]
        self.assertEqual(set(net(loss_pct=1)), {"rtt_ms", "loss_pct", "rate_mbit"})
        for bad in ({"delay_jitter_ms": 0}, {"delay_jitter_ms": 25}, {"delay_spike_ms": 100},
                    {"delay_spike_ms": 100, "delay_spike_len_ms": 200, "delay_spike_pct": 0},
                    {"loss_pct": 1, "loss_outage_ms": 30, "delay_spike_ms": 100, "delay_spike_len_ms": 200, "delay_spike_pct": 1}):
            with self.assertRaises(plan.PlanError):
                net(**bad)
        # A varying delay without a rate reorders packets; the rate keeps the queue in order.
        self.assertEqual(cell.netem_args(net(delay_jitter_ms=5)),
                         ["netem", "delay", "20ms", "5ms", "loss", "0%", "rate", "10gbit", "limit", "100000"])
        self.assertEqual(cell.netem_args(net(delay_jitter_ms=5, rate_mbit=200))[-4:], ["rate", "200mbit", "limit", "100000"])
        n = net(loss_pct=0.5, delay_spike_ms=150, delay_spike_len_ms=300, delay_spike_pct=2)
        self.assertEqual(cell.netem_args(n), ["netem", "delay", "20ms", "loss", "0.5%", "rate", "10gbit", "limit", "100000"])
        self.assertEqual(cell.netem_args(n, out=True)[:3], ["netem", "delay", "170ms"])
        self.assertIn("всплески +150 мс по 300 мс, 2% времени", report.net_title(n))

    def test_tcp_info_is_read_per_connection(self):
        out = ("0 0 127.0.0.1:41443 127.0.0.1:50000 \n"
               "\t cubic rto:252 backoff:2 rtt:50.1/3.2 bytes_sent:900 bytes_retrans:300 segs_out:40 data_segs_out:30"
               " retrans:1/7 lost:1 dsack_dups:2 reordering:4\n"
               "0 0 127.0.0.1:50000 127.0.0.1:41443 \n"
               "\t cubic rto:251 rtt:50.0/2.9 bytes_sent:500 segs_out:20 data_segs_out:10\n")
        socks = cell.parse_ss(out)
        self.assertEqual(socks[("127.0.0.1:41443", "127.0.0.1:50000")],
                         {"rto": 252, "backoff": 2, "bytes_sent": 900, "bytes_retrans": 300, "segs_out": 40,
                          "data_segs_out": 30, "retrans": 7, "lost": 1, "dsack_dups": 2, "reordering": 4})
        self.assertNotIn("retrans", socks[("127.0.0.1:50000", "127.0.0.1:41443")])
        t = cell.TCPStats(41443)
        t.poll = lambda: None
        for k, v in socks.items():
            t.conns[k] = v
        t.start()
        sides = t.stop()
        self.assertEqual(sides["server"]["retrans"], 7)
        self.assertEqual(sides["client"]["data_segs_out"], 10)
        self.assertEqual(sides["client"]["retrans"], 0)

    def test_a_group_runs_its_series_as_one_unpinned_batch(self):
        p = raw_plan(cpus={}, series=[{"name": "lo", "rounds": 1},
                                      {"name": "a", "network": {"rtt_ms": 40}, "group": "g", "rounds": 2},
                                      {"name": "b", "network": {"rtt_ms": 40, "loss_pct": 1}, "group": "g", "rounds": 2}])
        b = plan.expand(plan.resolve(p, "."))
        self.assertEqual([x["id"] for x in b][-2:], ["g/r1", "g/r2"])
        cells = b[-2]["cells"]
        self.assertEqual({c["series"] for c in cells}, {"a", "b"})
        self.assertEqual(len(cells), 10)
        self.assertTrue(all(c["cpus"] is None for c in cells))
        self.assertEqual([x["id"] for x in plan.expand(plan.resolve(p, "."), {"b"})], ["g/r1", "g/r2"])
        bad = [
            [{"name": "a", "group": "g"}],
            [{"name": "a", "network": {"rtt_ms": 40}, "group": "a"}],
            [{"name": "a", "network": {"rtt_ms": 40}, "group": "g"}, {"name": "b", "network": {"rtt_ms": 40}, "group": "g", "rounds": 2}],
        ]
        for series in bad:
            with self.assertRaises(plan.PlanError):
                plan.resolve(raw_plan(series=series), ".")

    def test_oversized_netem_round_splits_by_auth(self):
        p = raw_plan(cpus={"obfs": ["1", "2"], "wss": ["4", "5"]},
                     series=[{"name": "auth", "network": {"rtt_ms": 40}, "variants": ["a", "b"], "rounds": 2,
                              "auth": ["member", "password", "none"]}])
        b = plan.expand(plan.resolve(p, "."))
        self.assertEqual([x["id"] for x in b], ["auth/r1-member", "auth/r1-password", "auth/r1-none",
                                                "auth/r2-none", "auth/r2-password", "auth/r2-member"])
        self.assertEqual({(c["variant"], c["auth"]) for c in b[0]["cells"]}, {("a", "member"), ("b", "member")})
        self.assertEqual(len(b[0]["cells"]), 4)

    def test_shared_cpus_fail(self):
        p = raw_plan(cpus={"raw": "0", "obfs": ["1", "2"], "wss": ["2", "3"]}, series=[{"name": "n", "network": {"rtt_ms": 40}}])
        with self.assertRaises(plan.PlanError):
            plan.resolve(p, ".")

    def test_too_few_cpu_sets_fail(self):
        p = raw_plan(cpus={"raw": "0", "obfs": ["1"], "wss": ["3", "4"]}, series=[{"name": "n", "network": {"rtt_ms": 40}}])
        with self.assertRaises(plan.PlanError):
            plan.resolve(p, ".")

    def test_hash_follows_content(self):
        a = plan.resolve(raw_plan(), ".")["hash"]
        self.assertEqual(a, plan.resolve(raw_plan(), ".")["hash"])
        self.assertNotEqual(a, plan.resolve(raw_plan(series=[{"name": "lo", "rounds": 3}]), ".")["hash"])

    def test_cell_timeout_bounds_every_scenario(self):
        c = plan.expand(plan.resolve(raw_plan(defaults={"scenario_timeout": "1m", "hang_grace": "10s", "settle": "5s"}), "."))[1]["cells"][0]
        self.assertEqual(plan.cell_timeout(c, 10), 10 * 70 + 120 + 5)

    def test_wan_needs_its_section_and_owned_directories(self):
        wan = {"server": "root@192.0.2.1", "client": "router"}
        with self.assertRaises(plan.PlanError):
            plan.resolve(raw_plan(series=[{"name": "w", "network": "wan"}]), ".")
        p = plan.resolve(raw_plan(wan=wan, series=[{"name": "w", "network": "wan"}]), ".")
        self.assertEqual(p["wan"]["server_ip"], "192.0.2.1")
        for bad in ({"client_dir": "/opt/tmp"}, {"server_dir": "relative/s5bench"}, {"server_arch": "sparc"}, {"extra": 1}):
            with self.assertRaises(plan.PlanError, msg=bad):
                plan.resolve(raw_plan(wan=wan | bad, series=[{"name": "w", "network": "wan"}]), ".")
        # The unit's IP filter keeps a port without a password from being an open proxy.
        p = plan.resolve(raw_plan(wan=wan, series=[{"name": "w", "network": "wan", "transports": ["plain"], "auth": "none"}]), ".")
        self.assertEqual({c["transport"] for x in plan.expand(p) for c in x["cells"] if not c["direct"]}, {"plain"})
        with self.assertRaises(plan.PlanError):
            plan.resolve(raw_plan(wan=wan, series=[{"name": "w", "network": "wan", "transports": ["plain"]}]), ".")

    def test_wan_cells_run_one_at_a_time_in_alternating_order(self):
        p = plan.resolve(raw_plan(cpus={}, wan={"server": "root@192.0.2.1", "client": "router"},
                                  series=[{"name": "w", "network": "wan", "rounds": 2}]), ".")
        b = plan.expand(p)
        self.assertTrue(all(len(x["cells"]) == 1 and x["cells"][0]["cpus"] is None and x["cells"][0]["shape"] is None for x in b))
        ids = [x["id"] for x in b]
        self.assertEqual(ids[:3], ["w/raw-r1", "w/a-obfs-member-r1", "w/b-obfs-member-r1"])
        self.assertEqual(ids[5:8], ["w/b-wss-member-r2", "w/a-wss-member-r2", "w/b-obfs-member-r2"])
        c = b[1]["cells"][0]
        self.assertEqual(plan.cell_timeout(c, 1), seconds("5m") + seconds("30s") + 120 + 5 + 60)

    def test_wan_builds_for_both_hosts(self):
        from pipeline import build
        p = plan.resolve(raw_plan(wan={"server": "root@192.0.2.1", "client": "router", "client_arch": "arm64"},
                                  series=[{"name": "w", "network": "wan"}]), ".")
        need = build.targets(p)
        self.assertIn("arm64", need["matrix"])
        self.assertIn("arm64", need["s5client"])
        self.assertIn(build.HOST_ARCH, need["s5core"])
        self.assertEqual(build.arch_path("/b", "rc", "s5client", "arm64" if build.HOST_ARCH != "arm64" else "amd64").split("/")[-2][:6], "linux-")


class Wan(unittest.TestCase):
    def test_snapshot_line(self):
        from pipeline import wan
        self.assertEqual(wan.parse_snap("42 250 1000 1200 9 17", 100), {"cpu_s": 2.5, "rss_kb": 1000, "hwm_kb": 1200, "threads": 9, "fds": 17})
        self.assertIsNone(wan.parse_snap("42 gone", 100))

    def test_illegal_transitions_keep_their_names(self):
        body = """s5core_session_transitions_total{from="relay",illegal="false",region="protocol",to="half_closed",transport="plain"} 9
s5core_session_transitions_total{from="closed",illegal="true",region="protocol",to="half_closed",transport="plain"} 2
s5core_session_transitions_total{from="accepted",illegal="true",region="protocol",to="relay",transport="obfs"} 1
"""
        g = cell.parse_gauges(body)
        self.assertEqual(g["illegal_transitions"], 3)
        self.assertEqual(g["illegal_by"], {"protocol:closed->half_closed plain": 2, "protocol:accepted->relay obfs": 1})

    def test_runs_on_other_nodes_do_not_hold_each_other(self):
        from pipeline import run
        w = {"server": "root@a", "client": "root@r", "client_dir": "/opt/tmp/s5bench-a", "client_port": 41081}
        wan_a = {"series": [{"network": "wan"}], "wan": w}
        wan_b = {"series": [{"network": "wan"}], "wan": {**w, "server": "root@b", "client_dir": "/opt/tmp/s5bench-b", "client_port": 41082}}
        local = {"series": [{"network": {"rtt_ms": 50}}, {"network": "loopback"}]}
        a, b = {n for n, _ in run.machine_locks(wan_a)}, {n for n, _ in run.machine_locks(wan_b)}
        self.assertFalse(a & b)
        self.assertNotIn(".machine.lock", a)
        self.assertEqual([n for n, _ in run.machine_locks(local)], [".machine.lock"])
        self.assertNotEqual(a, {n for n, _ in run.machine_locks({**wan_a, "wan": {**w, "client_port": 41082}})})

    def test_ash_times(self):
        from pipeline import wan
        self.assertEqual(wan._ash_time("1m2.50s"), 62.5)
        self.assertEqual(wan._ash_time("0m0.000s"), 0.0)


class Recheck(unittest.TestCase):
    def test_recheck_plan_round_trips(self):
        p = plan.load(os.path.join(PLANS, "compare.toml"))
        rep = {"plan": p, "flags": [
            {"series": "loss", "transport": "wss", "a": {"variant": "v210", "auth": "member"}, "b": {"variant": "cur", "auth": "member"},
             "scenario": "h3/small-reuse", "metric": "p90_ms"},
            {"series": "yield", "transport": "wss", "a": {"variant": "cur", "auth": "member"}, "b": {"variant": "cury0", "auth": "member"},
             "scenario": analysis.CELL_ROW, "metric": "cpu_s"},
            {"series": "auth", "transport": "obfs", "a": {"variant": "cur", "auth": "member"}, "b": {"variant": "cur", "auth": "password"},
             "scenario": "tcp/connect", "metric": "p50_ms"},
        ]}
        text = report.recheck_toml(rep, 10)
        tomllib.loads(text)
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(text)
        try:
            r = plan.load(f.name)
        finally:
            os.unlink(f.name)
        s = {x["name"]: x for x in r["series"]}
        self.assertEqual(set(s), {"loss", "yield", "auth"})
        self.assertEqual(s["loss"]["only"], ["=h3/small-reuse"])
        self.assertEqual(s["loss"]["transports"], ["wss"])
        self.assertEqual(s["loss"]["rounds"], 10)
        self.assertEqual(s["yield"]["compare"], [["cur", "cury0"]])
        self.assertEqual(s["auth"]["compare"], [])
        self.assertEqual(s["auth"]["settings"]["auth"], ["member", "password", "fallback", "none"])
        self.assertEqual(r["variants"]["cury0"]["patch"], p["variants"]["cury0"]["patch"])

    def test_no_flags_no_plan(self):
        self.assertIsNone(report.recheck_toml({"plan": plan.load(os.path.join(PLANS, "quick.toml")), "flags": []}, 10))


if __name__ == "__main__":
    unittest.main()
