package udpbuf

import "os"

// ReceiveDrops is how many datagrams the kernel dropped for a full receive
// buffer, IPv4 and IPv6 together. The count belongs to the network
// namespace, not to the process: in a container it is the server's alone, on
// a host it takes in every UDP socket there. ok is false where the kernel does
// not say; a host without IPv6 has only the IPv4 count.
func ReceiveDrops() (n uint64, ok bool) {
	b, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0, false
	}
	if n, ok = parseSNMP(string(b)); !ok {
		return 0, false
	}
	if b, err := os.ReadFile("/proc/net/snmp6"); err == nil {
		if v6, ok := parseSNMP6(string(b)); ok {
			n += v6
		}
	}
	return n, true
}
