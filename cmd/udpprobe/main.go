// Command udpprobe measures what UDP costs when it is carried inside the
// tunnel instead of on its own.
//
// Plan task Ф4-10. The custom 0x83 command multiplexes every UDP flow of a
// session onto one TCP connection, which is what closes the WebRTC, QUIC and
// DNS leaks - and which means one lost segment stops delivery for all of them
// until it is retransmitted. That is a known price with an unknown number on
// it, and a number is what this probe produces: round-trip time and jitter of
// a UDP flow, through the tunnel and beside it, over a link with loss.
//
// It has two sides:
//
//	udpprobe -echo :9999
//	udpprobe -target 10.0.0.2:9999 -socks 127.0.0.1:1080 -n 300 -label tunnel
//
// Without -socks the packets go straight to the target, which is the control
// measurement: the same loss, the same path, no tunnel.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"time"
)

func main() {
	echo := flag.String("echo", "", "run as a UDP echo server on this address")
	target := flag.String("target", "", "UDP destination to probe, host:port")
	socks := flag.String("socks", "", "SOCKS5 proxy for UDP ASSOCIATE; empty means send directly")
	count := flag.Int("n", 300, "how many packets to send")
	interval := flag.Duration("interval", 20*time.Millisecond, "gap between packets")
	size := flag.Int("size", 60, "packet size in bytes, DNS query sized by default")
	timeout := flag.Duration("timeout", 2*time.Second, "how long a reply may take before the packet counts as lost")
	label := flag.String("label", "probe", "name of this run, printed with the results")
	flag.Parse()

	if *echo != "" {
		if err := runEcho(*echo); err != nil {
			fmt.Fprintf(os.Stderr, "echo: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "either -echo or -target is required")
		os.Exit(2)
	}

	res, err := probe(settings{
		target:   *target,
		socks:    *socks,
		count:    *count,
		interval: *interval,
		size:     *size,
		timeout:  *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		os.Exit(1)
	}
	res.print(*label)
}

// runEcho answers every datagram with its own bytes. It never returns.
func runEcho(addr string) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()

	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if _, err := pc.WriteTo(buf[:n], from); err != nil {
			return err
		}
	}
}

type settings struct {
	target   string
	socks    string
	count    int
	interval time.Duration
	size     int
	timeout  time.Duration
}

type results struct {
	sent    int
	lost    int
	rtt     []time.Duration
	jitter  time.Duration
	elapsed time.Duration
}

func (r results) print(label string) {
	sort.Slice(r.rtt, func(i, j int) bool { return r.rtt[i] < r.rtt[j] })
	lossPct := 0.0
	if r.sent > 0 {
		lossPct = 100 * float64(r.lost) / float64(r.sent)
	}
	fmt.Printf("%s\tsent=%d\tlost=%d (%.1f%%)\tp50=%s\tp95=%s\tp99=%s\tmax=%s\tjitter=%s\n",
		label, r.sent, r.lost, lossPct,
		round(percentile(r.rtt, 0.50)), round(percentile(r.rtt, 0.95)),
		round(percentile(r.rtt, 0.99)), round(percentile(r.rtt, 1.0)),
		round(r.jitter))
}

func round(d time.Duration) time.Duration { return d.Round(100 * time.Microsecond) }

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// probe sends count packets and matches the replies by sequence number. It
// does not wait for a reply before sending the next packet: a flow that stops
// on every loss would measure the loss, not what the tunnel does with it.
func probe(s settings) (results, error) {
	dst, err := net.ResolveUDPAddr("udp", s.target)
	if err != nil {
		return results{}, fmt.Errorf("resolve %s: %w", s.target, err)
	}

	send, recv, cleanup, err := openPath(s, dst)
	if err != nil {
		return results{}, err
	}
	defer cleanup()

	if s.size < 12 {
		s.size = 12
	}

	sentAt := make([]time.Time, s.count)
	rtt := make([]time.Duration, 0, s.count)
	type arrival struct {
		seq  uint32
		when time.Time
	}
	arrivals := make(chan arrival, s.count)
	readErr := make(chan error, 1)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := recv(buf)
			if err != nil {
				readErr <- err
				return
			}
			if n < 12 {
				continue
			}
			arrivals <- arrival{seq: binary.BigEndian.Uint32(buf[0:4]), when: time.Now()}
		}
	}()

	payload := make([]byte, s.size)
	start := time.Now()
	for i := 0; i < s.count; i++ {
		binary.BigEndian.PutUint32(payload[0:4], uint32(i))
		binary.BigEndian.PutUint64(payload[4:12], uint64(time.Now().UnixNano()))
		sentAt[i] = time.Now()
		if _, err := send(payload); err != nil {
			return results{}, fmt.Errorf("send %d: %w", i, err)
		}
		if s.interval > 0 && i != s.count-1 {
			time.Sleep(s.interval)
		}
	}

	// Collect for as long as a reply may still be in flight.
	seen := make(map[uint32]bool, s.count)
	var jitter float64
	var lastTransit float64
	deadline := time.NewTimer(s.timeout)
	defer deadline.Stop()

collect:
	for len(seen) < s.count {
		select {
		case a := <-arrivals:
			if int(a.seq) >= s.count || seen[a.seq] {
				continue
			}
			seen[a.seq] = true
			d := a.when.Sub(sentAt[a.seq])
			rtt = append(rtt, d)
			// RFC 3550's jitter estimate: the smoothed difference between the
			// gaps at the sender and the gaps at the receiver. A tunnel that
			// holds packets back while it retransmits shows up here even when
			// the average round trip does not move.
			transit := float64(d)
			if len(rtt) > 1 {
				diff := math.Abs(transit - lastTransit)
				jitter += (diff - jitter) / 16
			}
			lastTransit = transit
		case err := <-readErr:
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				break collect
			}
			return results{}, fmt.Errorf("receive: %w", err)
		case <-deadline.C:
			break collect
		}
	}

	return results{
		sent:    s.count,
		lost:    s.count - len(rtt),
		rtt:     rtt,
		jitter:  time.Duration(jitter),
		elapsed: time.Since(start),
	}, nil
}

// openPath returns a send and a receive function for the chosen path: either
// a plain UDP socket, or one going through a SOCKS5 UDP association.
func openPath(s settings, dst *net.UDPAddr) (send func([]byte) (int, error), recv func([]byte) (int, error), cleanup func(), err error) {
	if s.socks == "" {
		c, err := net.DialUDP("udp", nil, dst)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dial %s: %w", dst, err)
		}
		return c.Write, c.Read, func() { _ = c.Close() }, nil
	}

	ctrl, relay, err := associate(s.socks, s.timeout)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		_ = ctrl.Close()
		return nil, nil, nil, fmt.Errorf("dial relay %s: %w", relay, err)
	}

	header := udpHeader(dst)
	out := make([]byte, 0, 65535)
	send = func(b []byte) (int, error) {
		out = append(out[:0], header...)
		out = append(out, b...)
		n, err := c.Write(out)
		return max(0, n-len(header)), err
	}
	recv = func(b []byte) (int, error) {
		buf := make([]byte, len(b)+len(header)+32)
		n, err := c.Read(buf)
		if err != nil {
			return 0, err
		}
		body, err := stripUDPHeader(buf[:n])
		if err != nil {
			return 0, err
		}
		return copy(b, body), nil
	}
	cleanup = func() {
		_ = c.Close()
		// The association lives as long as its TCP connection: closing it is
		// what tells the proxy the flow is over.
		_ = ctrl.Close()
	}
	return send, recv, cleanup, nil
}

// associate performs the SOCKS5 handshake and the UDP ASSOCIATE request, and
// returns the control connection together with the relay address to send
// datagrams to.
func associate(proxy string, timeout time.Duration) (net.Conn, *net.UDPAddr, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(context.Background(), "tcp", proxy)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy %s: %w", proxy, err)
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = c.Close()
		return nil, nil, err
	}

	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("greeting reply: %w", err)
	}
	if greeting[1] != 0x00 {
		_ = c.Close()
		return nil, nil, fmt.Errorf("proxy wants authentication method %#x", greeting[1])
	}

	// ASSOCIATE with an unspecified source: the application does not know
	// which port it will send from until the proxy answers.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(req); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("associate: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("associate reply: %w", err)
	}
	if head[1] != 0x00 {
		_ = c.Close()
		return nil, nil, fmt.Errorf("associate refused with %#x", head[1])
	}

	var host string
	switch head[3] {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(c, ip); err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		host = net.IP(ip).String()
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(c, ip); err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		host = net.IP(ip).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		host = string(name)
	default:
		_ = c.Close()
		return nil, nil, fmt.Errorf("associate reply has address type %#x", head[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		_ = c.Close()
		return nil, nil, err
	}

	// The proxy may answer with an unspecified address, which means "the one
	// you are already talking to".
	if host == "0.0.0.0" || host == "::" {
		host, _, _ = net.SplitHostPort(c.RemoteAddr().String())
	}
	relay, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))))
	if err != nil {
		_ = c.Close()
		return nil, nil, err
	}

	// The association outlives the handshake, so the deadline must not.
	if err := c.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	return c, relay, nil
}

// udpHeader builds the SOCKS5 datagram header: no fragmentation, address of
// the final destination.
func udpHeader(dst *net.UDPAddr) []byte {
	h := []byte{0x00, 0x00, 0x00}
	if ip4 := dst.IP.To4(); ip4 != nil {
		h = append(h, 0x01)
		h = append(h, ip4...)
	} else {
		h = append(h, 0x04)
		h = append(h, dst.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(h, uint16(dst.Port))
}

func stripUDPHeader(b []byte) ([]byte, error) {
	if len(b) < 10 {
		return nil, fmt.Errorf("datagram shorter than a header: %d bytes", len(b))
	}
	switch b[3] {
	case 0x01:
		return b[10:], nil
	case 0x04:
		return b[22:], nil
	case 0x03:
		l := int(b[4])
		if len(b) < 7+l {
			return nil, fmt.Errorf("datagram shorter than its declared name: %d bytes", len(b))
		}
		return b[7+l:], nil
	default:
		return nil, fmt.Errorf("datagram has address type %#x", b[3])
	}
}
