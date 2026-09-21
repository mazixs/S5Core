// Command fpprobe asks a real network path what it does with the first packet
// of a connection.
//
// Level 1 of the stealth checklist (internal/stealth) states the rule that
// blocks fully encrypted traffic: the first packet with a payload is dropped
// unless it matches one of five exceptions, and an ideally random packet
// matches none of them. pkg/obfs/demo_test.go checks our frames against that
// rule offline. This probe checks the rule itself, on the path the product
// actually runs over - level 3 of the same checklist, the only one that gives
// a real answer.
//
// It opens a TCP connection, writes one shaped packet, and reports whether
// that packet reached the other end. Reaching it is not "the server replied":
// a refused obfuscated connection stays silent for the whole handshake budget
// on purpose (RefuseLinger), so silence proves nothing. Delivery is read off
// the local TCP stack instead - bytes_acked from TCP_INFO counts what the peer
// acknowledged, whoever is listening and whatever it thinks of the bytes.
//
//	fpprobe -target 198.51.100.7:443 -shapes random,tls,http -n 15
//	fpprobe -target 198.51.100.7:443 -shapes random,tls -burst 16 -rounds 3
//
// A shape is what the first packet looks like:
//
//	random - uniformly random bytes, which is what an obfuscated frame is
//	tls    - a TLS record header (0x16 0x03 0x01 len) over random bytes
//	http   - a plausible HTTP request, padded
//	text   - printable ASCII only
//	printN - N bytes from the base64 alphabet, then random bytes to size
//
// Two modifiers apply to any shape: ":splitN" writes the same payload as N
// TCP segments instead of one, and "@N" overrides -size for that shape alone.
// So "random:split2", "tls:split3@512" and "random@64" are all shapes.
//
//	fpprobe -target 198.51.100.7:443 -shapes random,random:split2,random:split3
//
// splitN is the measurement behind the cheapest countermeasure available to
// us: the rule applies to the first TCP payload of a connection, so a first
// burst written as several segments may leave no packet for it to match. It
// needs no deception - both ends are ours, and the receiving TCP stack
// reassembles the stream as it always does - which is what separates it from
// the fake-packet techniques that break third-party services.
//
// Two effects are folded into one number here, and the sizes tell them apart.
// Splitting can desynchronise a filter that matches on the first payload, and
// it also shortens that payload, which changes Ex1: on sixteen random bytes
// the one-bit density leaves the [3.4, 4.6] band often enough to matter, on
// 256 bytes almost never. Compare "random@64" against "random:split4" at 256
// to see which of the two is doing the work.
//
// On the path measured in docs/field/stealth.md the answer was the length
// alone: the filter classifies first packets of 100 bytes and up, and 99
// bytes pass whether they arrive whole or in pieces. Splitting helped only
// where it made the first segment short - "random:split3" (85 bytes first)
// passed, "random:split2" (128) did not. So the sizes are the experiment and
// the split is how a sender reaches those sizes without dropping payload.
//
// printN exists to find the shortest printable opening the path accepts. The
// rule's exceptions Ex2 and Ex4 are about the first six bytes and about a run
// of twenty; a path that passes print6 and drops random is applying the rule
// as written, and the answer decides how many bytes the wire format has to
// spend.
//
// The point of running more than one shape is the difference between them.
// A path that drops "random" and passes "tls" is classifying by content, and
// the numbers say how hard.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	target := flag.String("target", "", "host:port to probe (required)")
	shapes := flag.String("shapes", "random,tls", "comma-separated first-packet shapes: random, tls, http, text, printN")
	size := flag.Int("size", 256, "size of the first packet in bytes")
	n := flag.Int("n", 10, "probes per shape, per round")
	burst := flag.Int("burst", 0, "if set, open this many connections at once instead of one at a time")
	rounds := flag.Int("rounds", 1, "repeat the whole matrix this many times")
	settle := flag.Duration("settle", 2*time.Second, "how long to wait for the peer before reading TCP_INFO")
	dialTimeout := flag.Duration("dial-timeout", 5*time.Second, "give up on the TCP handshake after this")
	pause := flag.Duration("pause", 150*time.Millisecond, "wait between probes")
	splitGap := flag.Duration("split-gap", 3*time.Millisecond, "wait between the segments of a splitN shape, so the kernel does not merge them")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "-target is required")
		os.Exit(2)
	}
	wanted, err := parseShapes(*shapes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *size < 16 {
		fmt.Fprintln(os.Stderr, "-size below 16 bytes cannot carry every shape")
		os.Exit(2)
	}
	for _, s := range wanted {
		if s.splits > 1 && s.sizeFor(*size)/s.splits < 1 {
			fmt.Fprintf(os.Stderr, "shape %q: %d bytes do not divide into %d segments\n", s.name, s.sizeFor(*size), s.splits)
			os.Exit(2)
		}
	}

	run := probeOne
	if *burst > 0 {
		run = func(target string, s shape, size int, d dialSettings) (result, error) {
			return probeBurst(target, s, size, *burst, d)
		}
	}

	totals := map[string]*result{}
	for _, s := range wanted {
		totals[s.name] = &result{}
	}
	dial := dialSettings{timeout: *dialTimeout, settle: *settle, splitGap: *splitGap}

	for round := 1; round <= *rounds; round++ {
		for _, s := range wanted {
			var got result
			reps := *n
			if *burst > 0 {
				reps = 1
			}
			for i := 0; i < reps; i++ {
				r, err := run(*target, s, *size, dial)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", s.name, err)
				}
				got.add(r)
				time.Sleep(*pause)
			}
			totals[s.name].add(got)
			if *rounds > 1 {
				fmt.Printf("round %d  %-14s %s\n", round, s.name, got)
			}
		}
	}

	if *rounds > 1 {
		fmt.Println()
	}
	// The name column is as wide as the widest shape asked for: a spelling
	// like "tls:split3@512" is a name, and a report that wraps it is harder
	// to read than one with a wide column.
	width := len("shape")
	for _, s := range wanted {
		width = max(width, len(s.name))
	}
	fmt.Printf("%-*s %-22s %s\n", width, "shape", "first packet delivered", "unreachable")
	for _, s := range wanted {
		t := totals[s.name]
		fmt.Printf("%-*s %-22s %d\n", width, s.name, t.String(), t.unreachable)
	}
}

// result counts the outcomes of a set of probes. delivered and lost are the
// two answers the probe exists for; unreachable is everything that never got
// far enough to ask - a refused or timed-out TCP handshake, which is a
// different failure and must not be averaged into the other two.
type result struct {
	delivered   int
	lost        int
	unreachable int
}

func (r *result) add(o result) {
	r.delivered += o.delivered
	r.lost += o.lost
	r.unreachable += o.unreachable
}

func (r result) String() string {
	total := r.delivered + r.lost
	if total == 0 {
		return "no usable probes"
	}
	return fmt.Sprintf("%d/%d (%.0f%%)", r.delivered, total, 100*float64(r.delivered)/float64(total))
}

type dialSettings struct {
	timeout  time.Duration
	settle   time.Duration
	splitGap time.Duration
}

// dial opens one TCP connection under the probe's budget. The context is the
// same for every probe: the deadline that matters is the per-connection one,
// and a probe that hangs past it is exactly the "unreachable" outcome.
func (d dialSettings) dial(target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: d.timeout}
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	return dialer.DialContext(ctx, "tcp", target)
}

// probeOne opens one connection, writes one shaped packet and decides whether
// it arrived.
func probeOne(target string, s shape, size int, d dialSettings) (result, error) {
	conn, err := d.dial(target)
	if err != nil {
		return result{unreachable: 1}, nil
	}
	defer conn.Close()

	if err := s.write(conn, s.sizeFor(size), d.splitGap); err != nil {
		return result{unreachable: 1}, nil
	}
	return judge(conn, d.settle)
}

// probeBurst opens several connections at once. A path that classifies by
// content usually reacts to a burst of look-alike connections more sharply
// than to the same probes spread out, so the burst is a separate measurement
// rather than a faster way to run the same one.
func probeBurst(target string, s shape, size int, count int, d dialSettings) (result, error) {
	conns := make([]net.Conn, 0, count)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	var out result
	for i := 0; i < count; i++ {
		conn, err := d.dial(target)
		if err != nil {
			out.unreachable++
			continue
		}
		if err := s.write(conn, s.sizeFor(size), d.splitGap); err != nil {
			conn.Close()
			out.unreachable++
			continue
		}
		conns = append(conns, conn)
	}

	// One wait for the whole burst: the connections were opened together and
	// the peer acknowledges them together.
	time.Sleep(d.settle)
	for _, c := range conns {
		acked, err := bytesAcked(c)
		switch {
		case err != nil:
			out.unreachable++
		case acked > ackedFloor:
			out.delivered++
		default:
			out.lost++
		}
	}
	return out, nil
}

// ackedFloor is the number of acknowledged bytes above which the payload
// itself must have arrived. The SYN counts as one, so anything above a few
// bytes means the peer saw data.
const ackedFloor = 10

// judge waits for the peer, then falls back to the local TCP stack. Any answer
// - data, an orderly close or a reset - proves the packet arrived. Silence
// proves nothing either way, which is where TCP_INFO comes in.
func judge(conn net.Conn, settle time.Duration) (result, error) {
	if err := conn.SetReadDeadline(time.Now().Add(settle)); err != nil {
		return result{unreachable: 1}, err
	}
	buf := make([]byte, 1)
	switch _, err := conn.Read(buf); {
	case err == nil, errors.Is(err, io.EOF):
		return result{delivered: 1}, nil
	case isTimeout(err):
		// fall through to TCP_INFO
	default:
		// A reset is still a reaction, so the peer received the packet.
		return result{delivered: 1}, nil
	}

	acked, err := bytesAcked(conn)
	if err != nil {
		return result{unreachable: 1}, err
	}
	if acked > ackedFloor {
		return result{delivered: 1}, nil
	}
	return result{lost: 1}, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// shape builds a first packet of a given size.
type shape struct {
	name  string
	build func(size int) []byte
	// splits is how many TCP segments the payload is written as. Zero and
	// one both mean a single write.
	splits int
	// size overrides the global -size for this shape. Zero means "use it".
	size int
}

// sizeFor is the packet size this shape asks for.
func (s shape) sizeFor(dflt int) int {
	if s.size > 0 {
		return s.size
	}
	return dflt
}

// write puts the shaped payload on the connection, as one segment or as
// s.splits of them.
//
// Nagle is off (Go sets TCP_NODELAY on every TCP connection), so each write
// is free to leave as its own segment - but "free to" is not "does". Linux
// also has auto-corking, which merges small writes while an earlier segment
// is still queued, and that is exactly the shape of this loop. The gap
// between writes is there to defeat it. It costs the probe a few
// milliseconds per connection and no round trips; a client that adopts this
// for real has the same problem to solve, and this is the place where it was
// first noticed.
//
// Whether the segments really arrived as segments is not knowable from here:
// TCP_INFO counts bytes, not packets. A path under suspicion deserves a
// tcpdump on one end to confirm it.
func (s shape) write(conn net.Conn, size int, gap time.Duration) error {
	pkt := s.build(size)
	if s.splits < 2 {
		_, err := conn.Write(pkt)
		return err
	}
	per := len(pkt) / s.splits
	if per == 0 {
		per = 1
	}
	for off := 0; off < len(pkt); off += per {
		end := min(off+per, len(pkt))
		// The last segment takes the remainder rather than leaving a
		// one-byte tail behind, which would be a sixth segment nobody
		// asked for and a shape of its own.
		if len(pkt)-end < per {
			end = len(pkt)
		}
		if _, err := conn.Write(pkt[off:end]); err != nil {
			return err
		}
		if end == len(pkt) {
			break
		}
		time.Sleep(gap)
	}
	return nil
}

var shapes = []shape{
	{name: "random", build: func(size int) []byte { return randomBytes(size) }},
	{name: "tls", build: func(size int) []byte {
		// A TLS 1.0-versioned handshake record, which is exception Ex5 of the
		// level 1 rule: the bytes after the header stay random, so the only
		// difference from the "random" shape is five bytes of header.
		body := randomBytes(size - 5)
		return append([]byte{0x16, 0x03, 0x01, byte(len(body) >> 8), byte(len(body))}, body...)
	}},
	{name: "http", build: func(size int) []byte {
		req := []byte("GET /assets/app.js HTTP/1.1\r\nHost: cdn.example.com\r\nAccept: */*\r\n\r\n")
		return pad(req, size, 'A')
	}},
	{name: "text", build: func(size int) []byte { return pad(nil, size, 'x') }},
}

// base64Alphabet is the printable opening printN uses. It is not an arbitrary
// choice of printable bytes: the wire format encodes its prologue this way, so
// a measurement with this alphabet measures the format we can actually ship.
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// printable builds N bytes drawn uniformly from that alphabet followed by
// random bytes. The random tail is what makes the shape comparable to
// "random": the only difference between them is the opening.
func printable(n int) shape {
	return shape{name: fmt.Sprintf("print%d", n), build: func(size int) []byte {
		if n > size {
			n = size
		}
		out := randomBytes(size)
		for i := 0; i < n; i++ {
			out[i] = base64Alphabet[int(out[i])%len(base64Alphabet)]
		}
		return out
	}}
}

// parseShapes reads the -shapes list. A name is a base shape with optional
// modifiers: ":splitN" for the number of TCP segments and "@N" for a size of
// its own. The full spelling stays as the shape's name, so the report names
// the thing that was measured.
func parseShapes(list string) ([]shape, error) {
	var out []shape
	for _, spec := range strings.Split(list, ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		s, err := parseShape(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("-shapes is empty")
	}
	return out, nil
}

func parseShape(spec string) (shape, error) {
	rest := spec
	size := 0
	if base, digits, ok := strings.Cut(rest, "@"); ok {
		n, err := strconv.Atoi(digits)
		if err != nil || n < 1 {
			return shape{}, fmt.Errorf("shape %q: @N needs a positive size", spec)
		}
		rest, size = base, n
	}
	splits := 0
	if base, mod, ok := strings.Cut(rest, ":"); ok {
		digits, isSplit := strings.CutPrefix(mod, "split")
		n, err := strconv.Atoi(digits)
		if !isSplit || err != nil || n < 1 {
			return shape{}, fmt.Errorf("shape %q: the only modifier is :splitN with a positive count", spec)
		}
		rest, splits = base, n
	}

	s, err := baseShape(rest, spec)
	if err != nil {
		return shape{}, err
	}
	s.name = spec
	s.splits = splits
	s.size = size
	return s, nil
}

func baseShape(name, spec string) (shape, error) {
	if digits, ok := strings.CutPrefix(name, "print"); ok {
		n, err := strconv.Atoi(digits)
		if err != nil || n < 1 {
			return shape{}, fmt.Errorf("shape %q: printN needs a positive byte count", spec)
		}
		return printable(n), nil
	}
	for _, s := range shapes {
		if s.name == name {
			return s, nil
		}
	}
	known := make([]string, 0, len(shapes)+1)
	for _, s := range shapes {
		known = append(known, s.name)
	}
	known = append(known, "printN")
	sort.Strings(known)
	return shape{}, fmt.Errorf("unknown shape %q (known: %s, each with optional :splitN and @size)", spec, strings.Join(known, ", "))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return b
}

func pad(prefix []byte, size int, filler byte) []byte {
	out := make([]byte, size)
	n := copy(out, prefix)
	for i := n; i < size; i++ {
		out[i] = filler
	}
	return out
}
