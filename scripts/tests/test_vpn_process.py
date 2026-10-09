import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('vpn_process', Path(__file__).parents[1] / 'vpn_process.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)


@unittest.skipUnless(sys.platform == 'linux', 'Linux pidfds and /proc are required')
class OwnedChildTests(unittest.TestCase):
    def test_reused_pid_or_wrong_executable_cannot_be_signalled(self):
        with subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(20)']) as child:
            try:
                state = vpn.identity(child.pid)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'process.json'
                    wrong = dict(state, start=str(int(state['start']) - 1))
                    path.write_text(json.dumps(wrong))
                    self.assertFalse(vpn.act(path, state['exe'], stop=True))
                    path.write_text(json.dumps(state))
                    self.assertFalse(vpn.act(path, '/different/binary', stop=True))
                    self.assertIsNone(child.poll())
                    self.assertTrue(vpn.act(path, state['exe']))
                    self.assertTrue(vpn.act(path, state['exe'], stop=True))
                    self.assertEqual(child.wait(timeout=2), -15)
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=2)
