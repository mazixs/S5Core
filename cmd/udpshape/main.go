// Command udpshape measures which shapes of UDP datagram cross a network path,
// uplink and downlink separately, to choose the wire shape of a UDP transport.
// The server answers every datagram with one of the same form and size that
// carries how many it has received; forms.go lists the forms (random, QUIC,
// DTLS, STUN and a WireGuard-like control) and the trailer that lets the
// server count them without knowing the form.
//
//	udpshape serve -listen :443,3478,51820 -log udpshape.jsonl
//	udpshape probe -to 198.51.100.7:443,3478 -sizes 200,1200 -count 200
//	udpshape probe -to 198.51.100.7:443 -sustain quic-short@1200 -duration 60s
//
// Results go to docs/field/, next to the TCP first-packet numbers of cmd/fpprobe.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serveMain(os.Args[2:])
	case "probe":
		err = probeMain(os.Args[2:])
	case "help", "-h", "-help", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "udpshape: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	var ue usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
	case errors.Is(err, errFlags):
		os.Exit(2)
	case errors.As(err, &ue):
		fmt.Fprintln(os.Stderr, "udpshape:", err)
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "udpshape:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  udpshape serve -listen [HOST]:PORT[,PORT...] [-allow CIDR,...] [-log FILE]
  udpshape probe -to HOST:PORT[,PORT...] [-forms LIST] [-sizes LIST] [-count N] [-rate PPS] [-json]
  udpshape probe -to HOST:PORT -sustain FORM@SIZE [-duration D] [-window D] [-rate PPS] [-json]

forms: %s
"udpshape serve -h" and "udpshape probe -h" list every flag.
`, formNames())
}

// usageError is a bad command line, exit status 2.
type usageError string

func (e usageError) Error() string { return string(e) }

func usagef(format string, a ...any) error { return usageError(fmt.Sprintf(format, a...)) }

// errFlags is a parse error the flag package has already printed.
var errFlags = errors.New("bad flags")

func flagError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	return errFlags
}

// parseHostPorts reads HOST:PORT[,PORT...]. Later items give the port alone
// or repeat the host; a list names one host.
func parseHostPorts(s string) (string, []int, error) {
	var host string
	var ports []int
	seen := map[int]bool{}
	for i, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		h, p := "", item
		if strings.Contains(item, ":") {
			var err error
			if h, p, err = net.SplitHostPort(item); err != nil {
				return "", nil, usagef("%q: %v", item, err)
			}
		}
		if i == 0 {
			host = h
		} else if h != "" && h != host {
			return "", nil, usagef("%q: one host per list, the first item names it", s)
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", nil, usagef("%q: port must be 1-65535", item)
		}
		if seen[port] {
			return "", nil, usagef("%q: port %d listed twice", s, port)
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return host, ports, nil
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, usagef("-allow %q: %v", item, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, usagef("-allow %q: %v", item, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
