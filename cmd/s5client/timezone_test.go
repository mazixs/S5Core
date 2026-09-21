package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// dialLog records every outbound connection the client attempts. Because the
// binary has exactly one dialler, an empty log is proof that nothing went out
// - not merely that the one call the test knew about was skipped.
type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (l *dialLog) record(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.addrs = append(l.addrs, addr)
}

func (l *dialLog) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.addrs...)
}

var errHookedDial = errors.New("dial blocked by the test hook")

// hookDials replaces the client's only outbound dialler for the duration of
// one test.
func hookDials(t *testing.T) *dialLog {
	t.Helper()
	log := &dialLog{}
	original := dialOutbound
	dialOutbound = func(ctx context.Context, network, addr string) (net.Conn, error) {
		log.record(addr)
		return nil, errHookedDial
	}
	t.Cleanup(func() { dialOutbound = original })
	return log
}

// The client used to call ipapi.co on every start, handing a third party the
// pairing "this client uses this proxy" and putting a recognisable request on
// the wire immediately before every connection to the proxy.
func TestStartupContactsNobodyByDefault(t *testing.T) {
	log := hookDials(t)

	startupChecks(clientParams{ServerAddr: "198.51.100.7:1443"})

	if addrs := log.seen(); len(addrs) != 0 {
		t.Fatalf("starting the client dialled %v, it must dial nothing", addrs)
	}
}

// The check itself is not gone, it is opt-in. Someone who wants it still gets
// it, and now knows they asked for it.
func TestTimezoneCheckStillWorksWhenAskedFor(t *testing.T) {
	log := hookDials(t)

	startupChecks(clientParams{ServerAddr: "198.51.100.7:1443", TimezoneCheck: true})

	addrs := log.seen()
	if len(addrs) == 0 {
		t.Fatal("TIMEZONE_CHECK=true made no request at all")
	}
	for _, addr := range addrs {
		if !strings.Contains(addr, "ipapi.co") {
			t.Fatalf("unexpected outbound connection to %q", addr)
		}
	}
}

// A private or loopback server address is nobody else's business either: the
// lookup would leak the client's own address for no possible answer.
func TestTimezoneCheckSkipsPrivateServerAddresses(t *testing.T) {
	log := hookDials(t)

	for _, addr := range []string{"127.0.0.1:1443", "10.0.0.5:1443", "192.168.1.2:1443", "vpn.example.com:1443"} {
		startupChecks(clientParams{ServerAddr: addr, TimezoneCheck: true})
	}

	if addrs := log.seen(); len(addrs) != 0 {
		t.Fatalf("looked up a non-public server address, dialled %v", addrs)
	}
}

// The tunnel itself goes through the same hook, which is what makes the
// assertion in TestStartupContactsNobodyByDefault meaningful: if a dial could
// bypass dialOutbound, an empty log would prove nothing.
func TestTheTunnelUsesTheSameDialler(t *testing.T) {
	log := hookDials(t)

	if _, err := dialServer(clientParams{ServerAddr: "198.51.100.7:1443"}); !errors.Is(err, errHookedDial) {
		t.Fatalf("dialServer bypassed the hook: %v", err)
	}
	if addrs := log.seen(); len(addrs) != 1 || addrs[0] != "198.51.100.7:1443" {
		t.Fatalf("dialServer dialled %v, want the server address once", addrs)
	}
}
