// Command idleprobe measures how long a tunnel survives while nothing is sent
// through it. It is the instrument behind the keepalive matrix (plan task
// Ф4-8): the question "does a middlebox on this path drop an idle connection,
// and after how long" has no answer that can be reasoned out, only measured,
// and the answer differs per path.
//
// It opens one connection through a SOCKS5 proxy to an echo target, confirms
// the path works, then goes quiet and probes at intervals until the
// connection breaks or the budget runs out.
//
//	# an echo target to aim at
//	idleprobe -echo 127.0.0.1:9101
//
//	# how long the tunnel lives while idle, through the local client
//	idleprobe -socks 127.0.0.1:1080 -target 127.0.0.1:9101 -budget 180s
//
// The exit status is 0 when the connection was still alive at the end of the
// budget and 1 when it broke, so a matrix run can branch on it.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	var (
		echo   = flag.String("echo", "", "run an echo server on this address instead of probing")
		socks  = flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy to tunnel through")
		target = flag.String("target", "", "echo server to reach through the proxy")
		budget = flag.Duration("budget", 180*time.Second, "how long to stay idle before giving up on a break")
		label  = flag.String("label", "", "name of this run, printed with the result")
	)
	flag.Parse()

	if *echo != "" {
		// runEcho only ever returns because something broke.
		fmt.Fprintln(os.Stderr, "echo:", runEcho(*echo))
		os.Exit(2)
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "-target is required")
		os.Exit(2)
	}

	alive, at, err := probe(*socks, *target, *budget)
	name := *label
	if name == "" {
		name = *target
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: setup failed: %v\n", name, err)
		os.Exit(2)
	}
	if alive {
		fmt.Printf("%s\talive\t>%s\n", name, budget.String())
		return
	}
	fmt.Printf("%s\tbroken\t%s\n", name, at.Round(time.Second))
	os.Exit(1)
}

func runEcho(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "echo listening on", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

// probe returns whether the connection was still alive when the budget ran
// out, and how long the silence had lasted when it broke if it did.
//
// The measurement is a silence, so it must not be interrupted to take it: the
// probe sends nothing and waits for the socket to break, which is what a proxy
// dropping an idle connection produces at this end. A box that instead
// forgets the connection without telling anyone leaves the socket looking
// open, so the budget ends with one round trip to tell the two apart.
func probe(socks, target string, budget time.Duration) (bool, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", socks)
	if err != nil {
		return false, 0, fmt.Errorf("dial proxy: %w", err)
	}
	defer conn.Close()

	if err := socks5Connect(conn, target); err != nil {
		return false, 0, err
	}

	// One round trip to be sure the path works before timing anything.
	if err := roundTrip(conn, "probe-0"); err != nil {
		return false, 0, fmt.Errorf("the tunnel did not work before the idle period: %w", err)
	}

	start := time.Now()
	if err := conn.SetDeadline(start.Add(budget)); err != nil {
		return false, 0, err
	}

	// Nothing should arrive: the far end is an echo server with nothing to
	// echo. Whatever ends this read is the answer.
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	idle := time.Since(start)
	switch {
	case err == nil:
		return false, idle, fmt.Errorf("the echo server sent %d bytes that were not asked for", len(buf))
	case isTimeout(err):
		// The silence lasted the whole budget. Confirm the tunnel still
		// carries data, for the boxes that drop state without a FIN.
		if err := roundTrip(conn, "probe-final"); err != nil {
			return false, idle, nil
		}
		return true, idle, nil
	default:
		return false, idle, nil
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func roundTrip(conn net.Conn, msg string) error {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo returned %q, want %q", buf, msg)
	}
	return nil
}

func socks5Connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("target port: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fmt.Errorf("greeting reply: %w", err)
	}
	if greeting[1] != 0x00 {
		return fmt.Errorf("the proxy asked for authentication method 0x%02x; idleprobe only speaks no-auth", greeting[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("the proxy refused the connection: 0x%02x", reply[1])
	}
	var rest int
	switch reply[3] {
	case 0x01:
		rest = 4 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		rest = int(l[0]) + 2
	case 0x04:
		rest = 16 + 2
	default:
		return fmt.Errorf("the proxy replied with address type 0x%02x", reply[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, rest)); err != nil {
		return fmt.Errorf("connect reply address: %w", err)
	}
	return nil
}
