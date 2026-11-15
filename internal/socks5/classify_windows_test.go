package socks5

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/mazixs/S5Core/internal/relay"
)

// Every classifier reads the Winsock code, wrapped as the net package returns
// it, where the POSIX errno alone would miss it. WSAETIMEDOUT needs a silent
// peer to provoke and is checked by its wrapping.
func TestClassifiersReadTheWinsockCode(t *testing.T) {
	sock := func(call string, code syscall.Errno) error {
		return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError(call, code)}
	}
	timedOut := sock("wsarecv", windows.WSAETIMEDOUT)
	for _, tc := range []struct{ name, got, want string }{
		{"dial timeout", dialOutcome(sock("connectex", windows.WSAETIMEDOUT)), DialTimeout},
		{"setup timeout", string(classifyFailure(timedOut)), string(FailureTimeout)},
		{"association timeout", associationEnd(timedOut), EndedByTimeout},
		{"relay timeout", relayClosedBy(relay.Result{Err: timedOut}, false, false), ClosedByServerTimeout},
		{"setup closed", string(classifyFailure(sock("wsasend", windows.WSAECONNABORTED))), string(FailureClosed)},
		{"association reset", associationEnd(sock("wsarecv", windows.WSAECONNRESET)), EndedByReset},
		{"datagram too large", udpWriteFailure(sock("wsasendto", windows.WSAEMSGSIZE)), UDPDropTargetTooLarge},
		{"datagram without buffer", udpWriteFailure(sock("wsasendto", windows.WSAENOBUFS)), UDPDropTargetNoBuffer},
		{"datagram unreachable", udpWriteFailure(sock("wsasendto", windows.WSAEHOSTUNREACH)), UDPDropTargetUnreachable},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: classified as %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if !stayedLocal(sock("connectex", windows.WSAEAFNOSUPPORT)) {
		t.Error("a family this host lacks is taken for a network failure")
	}
}

// Real dials that fail before any reply: the outcome and the SOCKS5 reply
// follow the Winsock code, not the English text of its message.
func TestRealWinsockDialFailuresGetTheirReply(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	for _, tc := range []struct {
		name, addr, outcome string
		reply               uint8
	}{
		{"refused", closed, DialRefused, connectionRefused},
		// 0.0.0.0/8 is never a destination: connect fails before sending.
		{"unroutable network", "0.0.0.1:9", DialNoRoute, networkUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := net.DialTimeout("tcp", tc.addr, 5*time.Second)
			if err == nil {
				t.Fatalf("dial to %s succeeded", tc.addr)
			}
			if got := dialOutcome(err); got != tc.outcome {
				t.Errorf("outcome %q, want %q: %v", got, tc.outcome, err)
			}
			if got := dialFailureReply(err); got != tc.reply {
				t.Errorf("reply %d, want %d: %v", got, tc.reply, err)
			}
		})
	}
}
