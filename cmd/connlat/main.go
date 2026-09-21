// Command connlat measures how many round trips it takes to get the first
// byte of a connection, through the tunnel and beside it.
//
// Gate G4 of the plan chooses the first-frame authentication scheme, and its
// input is what 0-RTT would actually save. That is a count of round trips,
// not a wall-clock number: the 0.31 s a deployment reports depends on its
// link, but how many times the setup crosses it is a property of the
// protocol. So this probe runs over a link with a known, symmetric RTT and
// reports the setup in units of it.
//
// Two sides:
//
//	connlat -listen :9100
//	connlat -target 10.0.0.3:9100 -socks 127.0.0.1:1080 -rtt 50ms -label obfs
//
// The listening side writes one byte the moment it accepts, so "time to first
// byte" is the setup chain and nothing else - no application protocol, no
// server-side think time.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"time"
)

func main() {
	listen := flag.String("listen", "", "run as the target: accept TCP and write one byte immediately")
	target := flag.String("target", "", "TCP destination to measure, host:port")
	socks := flag.String("socks", "", "SOCKS5 proxy to go through; empty means connect directly")
	user := flag.String("user", "", "SOCKS5 username, if the proxy asks for one")
	pass := flag.String("pass", "", "SOCKS5 password")
	count := flag.Int("n", 20, "how many connections to open")
	rtt := flag.Duration("rtt", 0, "known round-trip time of the link; phases are also reported in units of it")
	timeout := flag.Duration("timeout", 10*time.Second, "give up on a connection after this")
	label := flag.String("label", "probe", "name of this run, printed with the results")
	flag.Parse()

	if *listen != "" {
		if err := runTarget(*listen); err != nil {
			fmt.Fprintf(os.Stderr, "listen: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "either -listen or -target is required")
		os.Exit(2)
	}

	res, err := run(settings{
		target:  *target,
		socks:   *socks,
		user:    *user,
		pass:    *pass,
		count:   *count,
		timeout: *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	res.print(*label, *rtt)
}

// runTarget answers every connection with one byte and closes it. It never
// returns.
func runTarget(addr string) error {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()

	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			_, _ = c.Write([]byte{0x01})
			// Hold the connection open briefly so the probe's close, not
			// ours, ends it - a RST racing the first byte would show up as
			// a lost measurement rather than as the timing it is.
			time.Sleep(50 * time.Millisecond)
		}(c)
	}
}

type settings struct {
	target  string
	socks   string
	user    string
	pass    string
	count   int
	timeout time.Duration
}

// sample is one connection, split into the phases a client can distinguish
// from the outside.
type sample struct {
	dial      time.Duration // TCP handshake to the first hop (the proxy, or the target itself)
	setup     time.Duration // SOCKS5 greeting, auth and CONNECT, until the reply arrives
	firstByte time.Duration // from the reply (or from the dial, when direct) to the target's first byte
	total     time.Duration
}

type results struct {
	samples []sample
	failed  int
}

func run(s settings) (results, error) {
	var res results
	for i := 0; i < s.count; i++ {
		one, err := measure(s)
		if err != nil {
			res.failed++
			if res.failed > s.count/2 {
				return res, fmt.Errorf("more than half the connections failed, last: %w", err)
			}
			continue
		}
		res.samples = append(res.samples, one)
		time.Sleep(20 * time.Millisecond)
	}
	if len(res.samples) == 0 {
		return res, fmt.Errorf("no connection completed")
	}
	return res, nil
}

func measure(s settings) (sample, error) {
	var out sample
	start := time.Now()

	first := s.target
	if s.socks != "" {
		first = s.socks
	}
	d := net.Dialer{Timeout: s.timeout}
	c, err := d.DialContext(context.Background(), "tcp", first)
	if err != nil {
		return out, fmt.Errorf("dial %s: %w", first, err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return out, err
	}
	out.dial = time.Since(start)

	if s.socks != "" {
		afterDial := time.Now()
		if err := socksConnect(c, s.target, s.user, s.pass); err != nil {
			return out, err
		}
		out.setup = time.Since(afterDial)
	}

	afterSetup := time.Now()
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return out, fmt.Errorf("first byte: %w", err)
	}
	out.firstByte = time.Since(afterSetup)
	out.total = time.Since(start)
	return out, nil
}

// socksConnect speaks RFC 1928 to the proxy. Greeting and CONNECT are not
// pipelined here: the probe talks to a proxy on localhost, where a round trip
// costs nothing, and keeping the phases separate is the point.
func socksConnect(c net.Conn, target, user, pass string) error {
	methods := []byte{0x05, 0x01, 0x00}
	if user != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := c.Write(methods); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return fmt.Errorf("greeting reply: %w", err)
	}
	switch sel[1] {
	case 0x00:
	case 0x02:
		if user == "" {
			return fmt.Errorf("the proxy asks for a password and none was given")
		}
		req := make([]byte, 0, 3+len(user)+len(pass))
		req = append(req, 0x01, byte(len(user)))
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := c.Write(req); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			return fmt.Errorf("auth reply: %w", err)
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("auth rejected: 0x%02x", ar[1])
		}
	default:
		return fmt.Errorf("the proxy selected method 0x%02x", sel[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("CONNECT rejected: 0x%02x", head[1])
	}
	var rest int
	switch head[3] {
	case 0x01:
		rest = 4 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		rest = int(l[0]) + 2
	case 0x04:
		rest = 16 + 2
	default:
		return fmt.Errorf("unknown address type in reply: 0x%02x", head[3])
	}
	if _, err := io.ReadFull(c, make([]byte, rest)); err != nil {
		return fmt.Errorf("connect reply tail: %w", err)
	}
	return nil
}

func (r results) print(label string, rtt time.Duration) {
	med := func(pick func(sample) time.Duration) time.Duration {
		v := make([]time.Duration, len(r.samples))
		for i, s := range r.samples {
			v[i] = pick(s)
		}
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		return v[len(v)/2]
	}

	dial := med(func(s sample) time.Duration { return s.dial })
	setup := med(func(s sample) time.Duration { return s.setup })
	fb := med(func(s sample) time.Duration { return s.firstByte })
	total := med(func(s sample) time.Duration { return s.total })

	in := func(d time.Duration) string {
		if rtt <= 0 {
			return ""
		}
		return fmt.Sprintf(" (%.2f RTT)", float64(d)/float64(rtt))
	}

	fmt.Printf("%s\tn=%d\tfailed=%d\tdial=%s%s\tsetup=%s%s\tfirst_byte=%s%s\ttotal=%s%s\n",
		label, len(r.samples), r.failed,
		round(dial), in(dial), round(setup), in(setup),
		round(fb), in(fb), round(total), in(total))
}

func round(d time.Duration) time.Duration {
	if d >= time.Millisecond {
		return d.Round(100 * time.Microsecond)
	}
	return d.Round(time.Microsecond)
}
