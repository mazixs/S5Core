"""Soak preparation, which runs neither the proxies nor the compiler."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1]/'performance-soak.py'
SPEC = importlib.util.spec_from_file_location('performance_soak', SCRIPT)
soak = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(soak)


class SoakPreparationTest(unittest.TestCase):
    def test_preparation_only_hashes_its_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root/'not-an-executable'
            fake.write_bytes(b'not executable; preparation must only hash this')
            output = root/'plan'
            command = [sys.executable, str(SCRIPT), '--server', str(fake),
                       '--client', str(fake), '--go', str(root/'absent-go'), '--out', str(output)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            plan = json.loads((output/'plan.json').read_text(encoding='utf-8'))
            self.assertEqual(plan['status'], 'prepared')
            self.assertEqual(len(plan['matrix']), 8)
            self.assertEqual(plan['minimum_seconds'], 288*60)
            self.assertIn('cmd/httpsprobe/performance_linux_test.go', plan['harness_sources_sha256'])
            self.assertEqual({path.name for path in output.iterdir()}, {'plan.json'})
            if sys.platform == 'linux':
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            second = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(json.loads((output/'plan.json').read_text())['status'], 'prepared')

    def test_inherited_settings_cannot_redirect_or_extend_a_case(self):
        row = soak.matrix(['wss'], ['idle-tunnel'])[0]
        inherited = {'S5_PERF_OBFS_ADDR': 'untrusted:1', 'S5_PERF_FLOW_CONTEXT': '1',
                     'S5_PERF_CYCLES': '9000', 'S5_DIAGNOSTICS_DIR': '/untrusted',
                     'GODEBUG': 'gctrace=1', 'GOFLAGS': '-race',
                     'GOMAXPROCS': '128', 'PATH': os.environ.get('PATH', '')}
        env = soak.fixture_env(inherited, row, Path('/local/server'), Path('/local/client'), Path('/new/out'))
        for key in ('S5_PERF_OBFS_ADDR', 'S5_PERF_FLOW_CONTEXT', 'S5_DIAGNOSTICS_DIR', 'GODEBUG', 'GOFLAGS'):
            self.assertNotIn(key, env)
        self.assertEqual(env['S5_PERF_CYCLES'], '3')
        self.assertEqual(env['GOMAXPROCS'], '2')
        self.assertEqual(env['S5_PERF_OUT'], str(Path('/new/out')))
        self.assertEqual(env['PATH'], inherited['PATH'])


if __name__ == '__main__':
    unittest.main()
