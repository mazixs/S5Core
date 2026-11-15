"""The ABBA driver's records, without a proxy workload."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1]/'performance-ab.py'
SPEC = importlib.util.spec_from_file_location('performance_ab', SCRIPT)
ab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ab)


def driver(root, probe_body, *extra):
    """Runs the driver over a stand-in probe; the binaries are only hashed."""
    probe = root/'probe'
    probe.write_text('#!'+sys.executable+'\nimport os\nfrom pathlib import Path\n'+probe_body)
    probe.chmod(0o700)
    binary = root/'binary'
    binary.write_bytes(b'identity only; never executed')
    command = [sys.executable, str(SCRIPT), '--probe', str(probe), '--out', str(root/'out'), '--rounds', '2', *extra]
    for flag in ('before-client', 'before-server', 'after-client', 'after-server'):
        command += ['--'+flag, str(binary)]
    return subprocess.run(command, capture_output=True, text=True, timeout=20)


class CPUIntervalTest(unittest.TestCase):
    def test_interval_requires_same_cgroup_quota_and_growing_counters(self):
        before = {'boot_id': 'boot', 'cgroup': '/owned', 'cgroup_device': 1, 'cgroup_inode': 2,
                  'cpu.max': 'max 100000', 'monotonic_ns': 1,
                  'cpu.stat': 'usage_usec 10\nnr_periods 5\nnr_throttled 2\nthrottled_usec 10\n'}
        after = dict(before, monotonic_ns=1000000001,
                     **{'cpu.stat': 'usage_usec 20\nnr_periods 6\nnr_throttled 3\nthrottled_usec 15\n'})
        observed = ab.cpu_interval(before, after)
        self.assertEqual(observed['delta'], {'usage_usec': 10, 'nr_periods': 1, 'nr_throttled': 1, 'throttled_usec': 5})
        self.assertTrue(observed['throttled'])
        self.assertEqual(observed['seconds'], 1)
        unthrottled = dict(after, **{'cpu.stat': 'usage_usec 20\nnr_periods 6\nnr_throttled 2\nthrottled_usec 10\n'})
        self.assertFalse(ab.cpu_interval(before, unthrottled)['throttled'])
        for name, change in (('new cgroup', {'cgroup_inode': 3}), ('quota changed', {'cpu.max': '25000 100000'}),
                             ('counter reset', {'cpu.stat': before['cpu.stat'].replace('usage_usec 10', 'usage_usec 0')})):
            with self.subTest(name=name):
                self.assertEqual(ab.cpu_interval(before, dict(after, **change))['status'], 'unknown')
        self.assertEqual(ab.cpu_interval({}, after)['status'], 'unknown')


@unittest.skipUnless(sys.platform == 'linux', 'requires Linux process groups and an executable stand-in')
class DriverTest(unittest.TestCase):
    def test_each_run_is_recorded_with_its_variant_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = driver(root, 'out = Path(os.environ["S5_PERF_OUT"])\nout.mkdir()\n'
                                  '(out/"diagnostics").write_text(os.environ.get("S5_PERF_DIAGNOSTICS", "unset"))\n',
                            '--after-env', 'S5_PERF_DIAGNOSTICS=1')
            self.assertEqual(result.returncode, 0, result.stderr)
            out = root/'out'
            metadata = json.loads((out/'environment.json').read_text())
            self.assertTrue(metadata['completed'])
            self.assertEqual(metadata['variant_environment'], {'before': {}, 'after': {'S5_PERF_DIAGNOSTICS': '1'}})
            self.assertEqual([row['variant'] for row in metadata['runs']], ['before', 'after', 'after', 'before'])
            self.assertEqual((out/'environment.json').stat().st_mode & 0o777, 0o600)
            for row in metadata['runs']:
                self.assertTrue(row['completed'])
                self.assertTrue(row['inputs_unchanged'])
                self.assertLess(row['before']['monotonic_ns'], row['after']['monotonic_ns'])
                self.assertIn('status', row['cpu_interval'])
                self.assertTrue('cgroup' in row['before'] or 'cgroup_v2' in row['before']['unavailable'])
                expected = '1' if row['variant'] == 'after' else 'unset'
                self.assertEqual((out/row['name']/'diagnostics').read_text(), expected)

    def test_replaced_input_fails_the_series(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = driver(root, 'Path(os.environ["S5_PERF_SERVER"]).write_bytes(b"changed")\n')
            self.assertNotEqual(result.returncode, 0)
            metadata = json.loads((root/'out'/'environment.json').read_text())
            self.assertFalse(metadata['completed'])
            self.assertEqual(len(metadata['runs']), 1)
            self.assertFalse(metadata['runs'][0]['completed'])
            self.assertFalse(metadata['runs'][0]['inputs_unchanged'])

    def test_variant_cannot_take_over_driver_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for setting in ('S5_PERF_OUT=/elsewhere', 'DIAGNOSTICS=1', 'S5_PERF_DIAGNOSTICS'):
                with self.subTest(setting=setting):
                    result = driver(root, 'raise SystemExit(1)\n', '--before-env', setting)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse((root/'out').exists())


if __name__ == '__main__':
    unittest.main()
