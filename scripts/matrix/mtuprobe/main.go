// Command mtuprobe measures what a narrow link does to UDP datagrams by size,
// for the stand scripts/matrix/mtu_stand.py (docs/benchmarks/mtu-native-2026-09-26.md):
//
//	echo   counts tagged datagrams and answers requests of a given size; also
//	       serves HTTP and HTTP/3 on a bare socket for the bulk and QUIC runs
//	sweep  sends every size through a SOCKS5 UDP association and directly,
//	       and records the delivery, the kernel counters and the server metrics
//	quic   runs an HTTP/3 transfer whose QUIC has a real socket: directly, or
//	       to a local forwarder that relays each datagram through SOCKS5 UDP
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mtuprobe echo|sweep|quic [flags]")
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "echo":
		runEcho(args)
	case "sweep":
		runSweep(args)
	case "quic":
		runQUIC(args)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// A tagged datagram: kind, run, size, sequence, then filler up to size.
const (
	hdrLen   = 11
	kindUp   = 'U'
	kindAsk  = 'D'
	kindBack = 'R'
)

func putHeader(b []byte, kind byte, run uint32, size int, seq uint32) {
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], run)
	binary.BigEndian.PutUint16(b[5:], uint16(size))
	binary.BigEndian.PutUint32(b[7:], seq)
}

func header(b []byte) (kind byte, run uint32, size int, seq uint32, ok bool) {
	if len(b) < hdrLen {
		return 0, 0, 0, 0, false
	}
	return b[0], binary.BigEndian.Uint32(b[1:]), int(binary.BigEndian.Uint16(b[5:])), binary.BigEndian.Uint32(b[7:]), true
}

// socksUDP is a SOCKS5 UDP association: the control connection and the
// socket that talks to the relay.
type socksUDP struct {
	ctl   net.Conn
	udp   *net.UDPConn
	relay *net.UDPAddr
}

func associate(socks string) (*socksUDP, error) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	ctl, err := net.DialTimeout("tcp", socks, 5*time.Second)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	fail := func(err error) (*socksUDP, error) { _ = ctl.Close(); _ = udp.Close(); return nil, err }
	_ = ctl.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := ctl.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var g [2]byte
	if _, err := io.ReadFull(ctl, g[:]); err != nil || g[1] != 0 {
		return fail(fmt.Errorf("socks greeting: %v %v", g, err))
	}
	if _, err := ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	var h [4]byte
	if _, err := io.ReadFull(ctl, h[:]); err != nil || h[1] != 0 {
		return fail(fmt.Errorf("socks associate: %v %v", h, err))
	}
	ip := make(net.IP, map[byte]int{1: 4, 4: 16}[h[3]])
	if len(ip) == 0 {
		return fail(fmt.Errorf("socks atyp %d", h[3]))
	}
	var p [2]byte
	if _, err := io.ReadFull(ctl, ip); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(ctl, p[:]); err != nil {
		return fail(err)
	}
	_ = ctl.SetDeadline(time.Time{})
	relay := &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(p[:]))}
	if ip.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	return &socksUDP{ctl: ctl, udp: udp, relay: relay}, nil
}

// socksHeader is the SOCKS5 UDP header the tunnel carries with each datagram
// to target: 10 bytes for IPv4, 22 for IPv6.
func socksHeader(target *net.UDPAddr) []byte {
	head := []byte{0, 0, 0}
	if v4 := target.IP.To4(); v4 != nil {
		head = append(append(head, 1), v4...)
	} else {
		head = append(append(head, 4), target.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(head, uint16(target.Port))
}

func (s *socksUDP) send(buf, head, payload []byte) error {
	b := append(append(buf[:0], head...), payload...)
	_, err := s.udp.WriteToUDP(b, s.relay)
	return err
}

// recv returns the payload of the next datagram from the relay.
func (s *socksUDP) recv(b []byte) ([]byte, error) {
	for {
		n, _, err := s.udp.ReadFromUDP(b)
		if err != nil {
			return nil, err
		}
		d := b[:n]
		if len(d) < 4 {
			continue
		}
		skip := map[byte]int{1: 10, 4: 22}[d[3]]
		if skip == 0 || len(d) < skip {
			continue
		}
		return d[skip:], nil
	}
}

// closed reports when the proxy ends the association.
func (s *socksUDP) closed() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, s.ctl)
		close(done)
	}()
	return done
}

func (s *socksUDP) Close() { _ = s.ctl.Close(); _ = s.udp.Close() }

// kernelKeys are the counters that say where a datagram went: fragments,
// reassembly, ICMP errors about size, socket errors and TCP path MTU probing.
var kernelKeys = regexp.MustCompile(`Frag|Reasm|DestUnreach|TooBig|Type3$|Type2$|MTUP|RcvbufErrors|SndbufErrors|InErrors|NoPorts|RetransSegs|TCPTimeouts`)

// readKernel reads the counters of the network namespace of pid ("self" for
// this process) from /proc/PID/net.
func readKernel(pid string) map[string]int64 {
	out := map[string]int64{}
	for _, f := range []string{"snmp", "netstat"} {
		fh, err := os.Open("/proc/" + pid + "/net/" + f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		var names []string
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			proto := strings.TrimSuffix(fields[0], ":")
			if _, err := strconv.ParseInt(fields[1], 10, 64); err != nil {
				names = fields[1:]
				continue
			}
			for i, v := range fields[1:] {
				if i < len(names) && kernelKeys.MatchString(names[i]) {
					n, _ := strconv.ParseInt(v, 10, 64)
					out[proto+names[i]] = n
				}
			}
		}
		_ = fh.Close()
	}
	if fh, err := os.Open("/proc/" + pid + "/net/snmp6"); err == nil {
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 2 && kernelKeys.MatchString(fields[0]) {
				n, _ := strconv.ParseInt(fields[1], 10, 64)
				out[fields[0]] = n
			}
		}
		_ = fh.Close()
	}
	return out
}

// hosts maps a name to the pid whose namespace it reads: -netns A=self,B=123.
type hosts map[string]string

func parseHosts(s string) hosts {
	h := hosts{}
	for _, kv := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			h[k] = v
		}
	}
	return h
}

func (h hosts) read() map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for name, pid := range h {
		out[name] = readKernel(pid)
	}
	return out
}

func kernelDelta(a, b map[string]map[string]int64) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for host, after := range b {
		for k, v := range after {
			if d := v - a[host][k]; d != 0 {
				if out[host] == nil {
					out[host] = map[string]int64{}
				}
				out[host][k] = d
			}
		}
	}
	return out
}

// httpc reaches the management link only: a proxy of the environment would
// take the scrape off the stand.
var httpc = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}

var metricLine = regexp.MustCompile(`^(s5core_native_udp_[a-z_]+)(\{[^}]*\})?\s+([0-9.eE+-]+)$`)

// scrape reads the native UDP series of the server; nil without a URL.
func scrape(url string) map[string]float64 {
	if url == "" {
		return nil
	}
	resp, err := httpc.Get(url)
	if err != nil {
		return map[string]float64{"scrape_error": 1}
	}
	defer resp.Body.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		m := metricLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		v, _ := strconv.ParseFloat(m[3], 64)
		out[m[1]+cleanLabels(m[2])] = v
	}
	return out
}

var dropLabels = regexp.MustCompile(`,?(otel_scope_[a-z_]+|job|instance)="[^"]*"`)

func cleanLabels(l string) string {
	l = dropLabels.ReplaceAllString(l, "")
	l = strings.Replace(l, "{,", "{", 1)
	if l == "{}" {
		return ""
	}
	return l
}

func metricDelta(a, b map[string]float64) map[string]float64 {
	if b == nil {
		return nil
	}
	out := map[string]float64{}
	for k, v := range b {
		if strings.HasSuffix(k, "_sessions") || strings.HasPrefix(k, "s5core_native_udp_sessions") {
			continue
		}
		if d := v - a[k]; d != 0 {
			out[k] = d
		}
	}
	return out
}

// metric sums the series of name whose labels contain every part.
func metric(m map[string]float64, name string, parts ...string) float64 {
	var s float64
next:
	for k, v := range m {
		if !strings.HasPrefix(k, name) {
			continue
		}
		for _, p := range parts {
			if !strings.Contains(k, p) {
				continue next
			}
		}
		s += v
	}
	return s
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	must(err)
	if path == "" || path == "-" {
		_, _ = os.Stdout.Write(append(b, '\n'))
		return
	}
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}
