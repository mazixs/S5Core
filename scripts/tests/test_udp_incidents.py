from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import udp_incidents as watch

LOCAL = ("192.0.2.4", 31981)
NAT = ("198.51.100.3", 42890)
PEER = ("203.0.113.19", 53001)
LISTENER_PORT = 49152


class UDPIncidentsTest(unittest.TestCase):
    def test_tcpdump_ipv4_and_ipv6(self):
        self.assertEqual(
            watch.parse_packet("1780000001.125432 veth4 In  IP 192.0.2.4.31981 > 203.0.113.19.53001: UDP, length 48"),
            watch.Packet(1780000001.125432, "veth4", False, LOCAL, PEER),
        )
        self.assertEqual(
            watch.parse_packet("1780000001.125432 veth4 P   IP 192.0.2.4.31981 > 203.0.113.19.53001: UDP, length 48"),
            watch.Packet(1780000001.125432, "veth4", False, LOCAL, PEER),
        )
        self.assertEqual(
            watch.parse_packet("1780000001.126001 eth0 Out IP6 2001:db8::1.31981 > 2001:db8::2.53001: UDP, length 48"),
            watch.Packet(1780000001.126001, "eth0", True, ("2001:db8::1", 31981), ("2001:db8::2", 53001)),
        )
        self.assertIsNone(watch.parse_packet("1780000001.12 eth0 Out IP bad.bad > bad.bad: UDP, length 48"))

    def test_docker_binding_and_listener_ports_are_discovered(self):
        replies = [
            '42 {"39182/udp":[{"HostIp":"0.0.0.0","HostPort":"53000"}],"8080/tcp":null}',
            '[{"ifindex":17,"ifname":"veth-a"},{"ifindex":1,"ifname":"lo"}]',
            '[{"link_index":17,"link_netnsid":0,"addr_info":[{"family":"inet","local":"192.0.2.4"},'
            '{"family":"inet6","local":"2001:db8::4"}]}, {"ifindex":1,"ifname":"lo"}]',
        ]
        with patch.object(watch, "run_text", side_effect=replies):
            self.assertEqual(watch.container_network("fixture"), (
                {("veth-a", "192.0.2.4"), ("veth-a", "2001:db8::4")}, frozenset({39182}),
            ))

    def test_conntrack_resolves_translated_address_and_port(self):
        reply = ("udp 17 123 src=192.0.2.4 dst=203.0.113.19 sport=31981 dport=53001 "
                 "src=203.0.113.19 dst=198.51.100.3 sport=53001 dport=42890 [ASSURED]")
        with patch.object(watch, "run_text", side_effect=[reply, '[{"dev":"wan0"}]']) as run:
            self.assertEqual(watch.resolve_outer(LOCAL, PEER), ("wan0", NAT, PEER))
            self.assertEqual(run.call_args_list[0].args[-4:],
                             ("--orig-port-src", str(LOCAL[1]), "--orig-port-dst", str(PEER[1])))
            self.assertEqual(run.call_args_list[1].args, ("ip", "-j", "route", "get", PEER[0], "from", NAT[0]))
        with patch.object(watch, "run_text", side_effect=subprocess.CalledProcessError(1, "conntrack")):
            self.assertIsNone(watch.resolve_outer(LOCAL, PEER))

    def test_gap_retains_both_sides_before_and_after_nat(self):
        reports = []
        collector = watch.Collector(0, reports.append, lambda local, peer: ("wan0", NAT, peer))
        collector.update_network({("veth-a", LOCAL[0])}, frozenset({LISTENER_PORT}))
        for n in range(8):
            at = 200 + n / 10
            collector.observe(watch.Packet(at, "veth-a", False, LOCAL, PEER), 0)
            collector.observe(watch.Packet(at + .01, "wan0", True, NAT, PEER), 0)
            collector.observe(watch.Packet(at + .02, "wan0", False, PEER, NAT), 0)
            collector.observe(watch.Packet(at + .03, "veth-a", True, PEER, LOCAL), 0)
        for n in range(10):
            at = 201 + n / 2
            collector.observe(watch.Packet(at, "veth-a", False, LOCAL, PEER), 0)
            collector.observe(watch.Packet(at + .01, "wan0", True, NAT, PEER), 0)
            collector.observe(watch.Packet(at + .01, "other", True, NAT, PEER), 0)
        self.assertEqual(len(collector.pending), 1)
        collector.observe(watch.Packet(207, "wan0", False, PEER, NAT), 0)
        collector.advance(265, 0)
        self.assertEqual(len(reports), 1)
        self.assertFalse(reports[0]["history_truncated"])
        self.assertEqual(reports[0]["external"]["local_port"], NAT[1])
        self.assertIn([200, 8, 8, 8, 8], reports[0]["samples"])
        self.assertIn([205, 2, 0, 2, 0], reports[0]["samples"])
        self.assertIn([207, 0, 0, 0, 1], reports[0]["samples"])

    def test_trigger_needs_established_flow_and_sustained_sends(self):
        flow = watch.Flow()
        self.assertFalse(any(flow.observe(200 + n / 2, True) for n in range(30)))
        for n in range(8):
            flow.observe(220 + n / 10, False)
        self.assertFalse(any(flow.observe(223 + n * 2, True) for n in range(20)))

    def test_container_replacement_refreshes_addresses_and_excludes_listener(self):
        collector = watch.Collector(0, self.fail)
        collector.update_network({("veth-a", LOCAL[0])}, frozenset({LISTENER_PORT}))
        collector.observe(watch.Packet(1, "veth-a", False, LOCAL, PEER), 0)
        self.assertEqual(len(collector.flows), 1)
        replacement = ("192.0.2.5", LOCAL[1])
        collector.update_network({("veth-b", replacement[0])}, frozenset({25000}))
        collector.observe(watch.Packet(2, "veth-a", False, LOCAL, PEER), 0)
        collector.observe(watch.Packet(2, "veth-b", False, (replacement[0], 25000), PEER), 0)
        self.assertFalse(collector.flows)
        collector.observe(watch.Packet(2, "veth-b", False, replacement, PEER), 0)
        self.assertEqual(list(collector.flows), [("veth-b", replacement, PEER)])


if __name__ == "__main__":
    unittest.main()
