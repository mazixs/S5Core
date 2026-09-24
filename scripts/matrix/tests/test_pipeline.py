import os
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pipeline import analysis, plan, report  # noqa: E402
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
        from pipeline import cell
        body = """s5core_session_transitions_total{from="relay",illegal="false",region="protocol",to="half_closed",transport="plain"} 9
s5core_session_transitions_total{from="closed",illegal="true",region="protocol",to="half_closed",transport="plain"} 2
s5core_session_transitions_total{from="accepted",illegal="true",region="protocol",to="relay",transport="obfs"} 1
"""
        g = cell.parse_gauges(body)
        self.assertEqual(g["illegal_transitions"], 3)
        self.assertEqual(g["illegal_by"], {"protocol:closed->half_closed plain": 2, "protocol:accepted->relay obfs": 1})

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
