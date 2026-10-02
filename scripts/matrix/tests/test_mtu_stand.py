import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import mtu_stand  # noqa: E402

TUNNEL = 's5core_native_udp_datagrams_total{direction="from_client",path="native"}'


def result(size, mode, up, down, n=200, kernel=None):
    return dict(size=size, mode=mode, sent=n, up=up, asked=n, down=down, kernel=kernel or {},
                metrics={TUNNEL: n} if mode == "tunnel" else None)


def cell(results):
    return dict(cell=dict(family=4, mtu=1400, ptb="filter", sizes="1300:1312:4", n=200, native_limit=1364),
                results=results, client_closed=[{}])


class UDPSummary(unittest.TestCase):
    def test_a_band_is_what_is_neither_direct_nor_zero(self):
        s = mtu_stand.udp_summary(cell([
            result(1300, "tunnel", 200, 200), result(1300, "direct", 200, 200),
            result(1304, "tunnel", 120, 200), result(1304, "direct", 200, 200),
            result(1308, "tunnel", 0, 0), result(1308, "direct", 200, 200),
        ]))
        self.assertEqual(s["partial_up"], [(1304, 60.0, 100.0)])
        self.assertEqual(s["partial_down"], [])
        self.assertEqual(s["native_ceiling_up"], 1300)

    def test_a_loss_of_direct_is_not_a_band_of_native(self):
        s = mtu_stand.udp_summary(cell([
            result(1300, "tunnel", 200, 200), result(1300, "direct", 199, 199),
        ]))
        self.assertEqual(s["partial_up"], [])
        self.assertEqual(s["above_direct_up"], [(1300, 100.0, 99.5)])

    def test_fragments_count_only_native_sizes_of_the_tunnel(self):
        frag = {"A": {"IpFragCreates": 400}, "B": {"Ip6ReasmOKs": 200}}
        s = mtu_stand.udp_summary(cell([
            result(1300, "tunnel", 200, 200, kernel=frag), result(1300, "direct", 200, 200, kernel=frag),
            result(1400, "tunnel", 200, 200, kernel=frag), result(1400, "direct", 200, 200),
        ]))
        self.assertEqual((s["native_frags_a"], s["native_reasm_b"]), (400, 200))


if __name__ == "__main__":
    unittest.main()
