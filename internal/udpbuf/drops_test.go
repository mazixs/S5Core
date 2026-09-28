package udpbuf

import "testing"

const snmp = `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 100
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
Udp: 16664114 3611 29566 10382177 29565 7 0 266594 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors
UdpLite: 0 0 0 0 99 0 0 0 0
`

func TestTheCountersAreReadFromTheirTables(t *testing.T) {
	if n, ok := parseSNMP(snmp); !ok || n != 29565 {
		t.Fatalf("Udp RcvbufErrors = %d %v, want 29565", n, ok)
	}
	if n, ok := parseSNMP6("Udp6InDatagrams \t 5\nUdp6RcvbufErrors                \t41\nUdpLite6RcvbufErrors 3\n"); !ok || n != 41 {
		t.Fatalf("Udp6RcvbufErrors = %d %v, want 41", n, ok)
	}
	for _, bad := range []string{"", "Udp: InDatagrams\n", "Udp: RcvbufErrors\nUdp: x\n", "UdpLite: RcvbufErrors\nUdpLite: 5\n"} {
		if n, ok := parseSNMP(bad); ok {
			t.Fatalf("%q parsed as %d", bad, n)
		}
	}
}
