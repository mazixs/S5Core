package udpbuf

import (
	"strconv"
	"strings"
)

// parseSNMP reads RcvbufErrors of the Udp table in /proc/net/snmp, which is
// a line of names followed by a line of values.
func parseSNMP(b string) (uint64, bool) {
	var names []string
	for _, line := range strings.Split(b, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = f[1:]
			continue
		}
		for i, name := range names {
			if name == "RcvbufErrors" && i+1 < len(f) {
				v, err := strconv.ParseUint(f[i+1], 10, 64)
				return v, err == nil
			}
		}
		return 0, false
	}
	return 0, false
}

// parseSNMP6 reads Udp6RcvbufErrors of /proc/net/snmp6, a name and a value
// per line.
func parseSNMP6(b string) (uint64, bool) {
	for _, line := range strings.Split(b, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "Udp6RcvbufErrors" {
			v, err := strconv.ParseUint(f[1], 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}
