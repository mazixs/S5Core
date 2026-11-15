package socks5

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Codes that loopback cannot provoke are checked as the net package wraps
// them: OpError around SyscallError around the Winsock Errno.
func TestWinsockErrorsKeepTheirBoundedFailureReasons(t *testing.T) {
	for _, tc := range []struct {
		name string
		code syscall.Errno
		udp  string
	}{
		{"message_size", windows.WSAEMSGSIZE, UDPDropTargetTooLarge},
		{"no_buffer", windows.WSAENOBUFS, UDPDropTargetNoBuffer},
		{"network_unreachable", windows.WSAENETUNREACH, UDPDropTargetUnreachable},
		{"host_unreachable", windows.WSAEHOSTUNREACH, UDPDropTargetUnreachable},
		{"refused", windows.WSAECONNREFUSED, UDPDropTargetUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("wsasendto", tc.code)}
			if got := udpWriteFailure(err); got != tc.udp {
				t.Fatalf("classified %v as %q, want %q", tc.code, got, tc.udp)
			}
		})
	}
	for _, code := range []syscall.Errno{windows.WSAECONNRESET, windows.WSAECONNABORTED, windows.WSAESHUTDOWN} {
		err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", code)}
		if associationEnd(err) != EndedByReset || classifyFailure(err) != FailureClosed {
			t.Fatalf("Winsock %d lost its association or failure classification", code)
		}
	}
	if !refused(windows.WSAECONNREFUSED) || !noRoute(windows.WSAENETUNREACH) || !stayedLocal(windows.WSAEAFNOSUPPORT) {
		t.Fatal("Winsock dial error depends on localized error text")
	}
	if socketErrno(errors.New("other"), syscall.ECONNRESET) || socketErrno(windows.WSAECONNRESET, syscall.ECONNREFUSED) {
		t.Fatal("unrelated error classified as socket failure")
	}
}

// What the stack returns on real loopback sockets. A peer that closes without
// a reset is reported as WSAECONNABORTED on the next write, not as a shutdown.
func TestRealWinsockFailuresAreClassified(t *testing.T) {
	pair := func(t *testing.T) (client, server *net.TCPConn) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		accepted := make(chan *net.TCPConn, 1)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c.(*net.TCPConn)
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		client = c.(*net.TCPConn)
		if server = <-accepted; server == nil {
			t.Fatal("no connection accepted")
		}
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		return client, server
	}
	closed := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("no error")
		}
		if classifyFailure(err) != FailureClosed || associationEnd(err) != EndedByReset {
			t.Fatalf("not classified as a closed connection: %v", err)
		}
	}

	t.Run("read after reset", func(t *testing.T) {
		client, server := pair(t)
		_ = server.SetLinger(0)
		_ = server.Close()
		_, err := client.Read(make([]byte, 1))
		closed(t, err)
	})
	t.Run("write after the peer closed", func(t *testing.T) {
		client, server := pair(t)
		_ = server.Close()
		var err error
		// The first write reaches the closed socket and draws the reset.
		for i := 0; i < 100 && err == nil; i++ {
			_, err = client.Write([]byte("x"))
			time.Sleep(20 * time.Millisecond)
		}
		closed(t, err)
	})
	t.Run("write after local shutdown", func(t *testing.T) {
		client, _ := pair(t)
		_ = client.CloseWrite()
		_, err := client.Write([]byte("x"))
		closed(t, err)
	})
	t.Run("dial refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		_, err = net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			t.Fatal("dial to a closed port succeeded")
		}
		if !refused(err) || dialOutcome(err) != DialRefused {
			t.Fatalf("refused dial classified as %q: %v", dialOutcome(err), err)
		}
	})
	t.Run("oversized datagram", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_, err = conn.WriteToUDP(make([]byte, 70000), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		if got := udpWriteFailure(err); err == nil || got != UDPDropTargetTooLarge {
			t.Fatalf("oversized datagram classified as %q: %v", got, err)
		}
	})
}
