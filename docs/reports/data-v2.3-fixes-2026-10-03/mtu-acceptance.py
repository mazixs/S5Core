import importlib.util
import os
from pathlib import Path
import subprocess
import sys

root = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/matrix/mtu_stand.py').is_file())
spec = importlib.util.spec_from_file_location('mtu_stand', root / 'scripts/matrix/mtu_stand.py')
stand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stand)
stand.QUIC_CELLS = [
    (4, 1500, 'pass', 0, True),
    (4, 1400, 'filter', 0, True),
    (6, 1500, 'pass', 0, True),
    (6, 1400, 'filter', 0, True),
    (4, 1500, 'filter', 0, True),
    (4, 1500, 'loss', 0, True),
    (6, 1500, 'filter', 0, True),
    (6, 1500, 'loss', 0, True),
]
base = stand.Stand
class AcceptanceStand(base):
    def up(self):
        super().up()
        if self.mtu == 1500 and self.ptb == 'filter':
            rules = 'table inet blocked_native {\n chain forward {\n type filter hook forward priority 0;\n udp dport 1444 drop;\n }\n}\n'
            subprocess.run(['ip', 'netns', 'exec', 'R1', 'nft', '-f', '-'], input=rules, text=True, check=True, env=stand.CLEAN)
        if self.ptb == 'loss':
            stand.nsx('R1', 'iptables' if self.fam == 4 else 'ip6tables', '-A', 'FORWARD', '-p', 'udp', '--dport', str(stand.PORT['udp']),
                      '-m', 'length', '--length', '1227:1428' if self.fam == 4 else '1247:1448', '-m', 'quota', '--quota', '8300' if self.fam == 4 else '8500', '-j', 'DROP')
        return self
    def down(self):
        if self.ptb == 'loss':
            counters = stand.nsx('R1', 'iptables' if self.fam == 4 else 'ip6tables', '-L', 'FORWARD', '-nvx').stdout
            Path(self.out, 'initial-size-loss.txt').write_text(counters)
        return super().down()
stand.Stand = AcceptanceStand
os.environ['MTU_STAND_INNER'] = '1'
sys.exit(stand.main())
