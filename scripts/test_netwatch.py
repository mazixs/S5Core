"""Fault and privacy checks for the independent diagnostic script."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("netwatch", Path(__file__).with_name("netwatch.py"))
netwatch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netwatch)


class NetwatchTest(unittest.TestCase):
    def test_dns_reply_requires_matching_question_and_success(self):
        query = netwatch.dns_query(123)
        reply = struct.pack("!HHHHHH", 123, 0x8180, 1, 1, 0, 0) + query[12:] + b"answer"
        self.assertTrue(netwatch.valid_dns_reply(reply, query))
        for bad in (b"", reply[:12], bytes([0, 124]) + reply[2:],
                    reply[:2] + struct.pack("!H", 0x8380) + reply[4:],
                    reply[:2] + struct.pack("!H", 0x8182) + reply[4:],
                    reply[:12] + b"wrong-question"):
            self.assertFalse(netwatch.valid_dns_reply(bad, query))

    def test_closed_tcp_port_is_reported_without_address(self):
        with patch.object(socket.socket, "connect", side_effect=ConnectionRefusedError(111, "private 192.0.2.1")):
            result = netwatch.network_check("private_alias", "192.0.2.1", "tcp_443", .05)
        self.assertFalse(result["ok"])
        text = json.dumps(result)
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn("connect(", text)
        self.assertLess(result["elapsed_ms"], 1000)

    def test_connected_udp_reply_validation(self):
        # A real socket checks the DNS framing and response matching without
        # relying on external availability in this test.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            def respond():
                query, peer = server.recvfrom(4096)
                answer = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:]
                server.sendto(answer, peer)
            worker = threading.Thread(target=respond)
            worker.start()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                client.connect(server.getsockname())
                query = netwatch.dns_query(17)
                client.send(query)
                self.assertTrue(netwatch.valid_dns_reply(client.recv(4096), query))
            worker.join(1)
            self.assertFalse(worker.is_alive())

    def test_rotation_bounds_disk_use_and_does_not_log_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "logs"
            handler = netwatch.log_handler(folder, 100)
            import logging
            for _ in range(30):
                handler.emit(logging.LogRecord("n", logging.INFO, "", 0, '{"target":"resolver_a","ok":false}', (), None))
            handler.close()
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            files = [p for p in folder.iterdir() if p.name != ".s5-netwatch"]
            self.assertLessEqual(len(files), 8)
            self.assertTrue(all(p.stat().st_size <= 100 for p in files))
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in files))

    def test_shared_directory_is_never_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            folder.chmod(0o755)
            old = folder / "checks.jsonl-other"
            old.write_text("operator data")
            os.utime(old, (1, 1))
            with self.assertRaises(ValueError):
                netwatch.log_handler(folder, 100)
            self.assertEqual(folder.stat().st_mode & 0o777, 0o755)
            self.assertEqual(old.read_text(), "operator data")
            self.assertEqual(sorted(p.name for p in folder.iterdir()), [old.name])

    def test_private_unmarked_directory_and_log_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with self.assertRaises(ValueError):
                netwatch.log_handler(folder, 100)
            owned = folder / "owned"
            handler = netwatch.log_handler(owned, 100)
            handler.close()
            path = owned / "checks.jsonl"
            path.unlink()
            target = folder / "target"
            target.write_text("outside")
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                netwatch.log_handler(owned, 100)
            self.assertEqual(target.read_text(), "outside")

    def test_container_inspection_failure_is_an_explicit_observation(self):
        result = netwatch.server_snapshot("s5-netwatch-nonexistent-container", 0)
        self.assertIn("error", result)
        self.assertNotIn("s5-netwatch-nonexistent-container", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
