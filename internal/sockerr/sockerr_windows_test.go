package sockerr

import (
	"errors"
	"net"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The mapping written out on its own: each POSIX errno matches exactly its
// Winsock codes and none of the others, as the net package wraps them
// (OpError around SyscallError around the Errno).
func TestEachPOSIXErrnoMatchesExactlyItsWinsockCodes(t *testing.T) {
	want := map[syscall.Errno][]syscall.Errno{
		syscall.ECONNRESET:   {windows.WSAECONNRESET, windows.WSAECONNABORTED},
		syscall.EPIPE:        {windows.WSAECONNABORTED, windows.WSAESHUTDOWN},
		syscall.ECONNREFUSED: {windows.WSAECONNREFUSED},
		syscall.ENETUNREACH:  {windows.WSAENETUNREACH},
		syscall.EHOSTUNREACH: {windows.WSAEHOSTUNREACH},
		syscall.EHOSTDOWN:    {windows.WSAEHOSTDOWN},
		syscall.EAFNOSUPPORT: {windows.WSAEAFNOSUPPORT},
		syscall.EMSGSIZE:     {windows.WSAEMSGSIZE},
		syscall.ENOBUFS:      {windows.WSAENOBUFS},
		syscall.EMFILE:       {windows.WSAEMFILE},
		syscall.ETIMEDOUT:    {windows.WSAETIMEDOUT},
	}
	var all []syscall.Errno
	for _, codes := range want {
		all = append(all, codes...)
	}
	for posix, codes := range want {
		if !Is(&net.OpError{Op: "dial", Net: "tcp", Err: posix}, posix) {
			t.Errorf("%v no longer matches itself", posix)
		}
		for _, code := range all {
			err := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", code)}
			if got, exp := Is(err, posix), slices.Contains(codes, code); got != exp {
				t.Errorf("Is(Winsock %d, %v) = %v, want %v", uint(code), posix, got, exp)
			}
		}
	}
	if Is(errors.New("connection reset by peer"), syscall.ECONNRESET) {
		t.Error("the error text is matched")
	}
}

// connect gives up on a silent peer with WSAETIMEDOUT, wrapped as connectex
// returns it, and net.Error.Timeout is false for that code.
func TestWinsockConnectTimeoutIsATimeout(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", windows.WSAETIMEDOUT)}
	if !Timeout(err) {
		t.Fatalf("%v is not a timeout", err)
	}
}

// What the stack returns on real sockets, for the codes that can be provoked
// without a network. A peer that closes without a reset is reported as
// WSAECONNABORTED on a later write, not as a shutdown.
func TestRealWinsockFailuresMatchTheirPOSIXErrno(t *testing.T) {
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
	is := func(t *testing.T, err error, codes ...syscall.Errno) {
		t.Helper()
		if err == nil {
			t.Fatal("no error")
		}
		for _, code := range codes {
			if !Is(err, code) {
				t.Fatalf("%v does not match %v", err, code)
			}
		}
	}

	t.Run("read after reset", func(t *testing.T) {
		client, server := pair(t)
		_ = server.SetLinger(0)
		_ = server.Close()
		_, err := client.Read(make([]byte, 1))
		is(t, err, syscall.ECONNRESET)
	})
	t.Run("write after the peer closed", func(t *testing.T) {
		client, server := pair(t)
		_ = server.Close()
		// A write reaches the closed socket and draws the reset, which a
		// later write reports. The deadline set by pair bounds the loop.
		var err error
		for err == nil {
			_, err = client.Write([]byte("x"))
		}
		is(t, err, syscall.ECONNRESET, syscall.EPIPE)
	})
	t.Run("write after local shutdown", func(t *testing.T) {
		client, _ := pair(t)
		_ = client.CloseWrite()
		_, err := client.Write([]byte("x"))
		is(t, err, syscall.EPIPE)
	})
	t.Run("dial refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		_, err = net.DialTimeout("tcp", addr, 5*time.Second)
		is(t, err, syscall.ECONNREFUSED)
	})
	t.Run("dial to an unroutable network", func(t *testing.T) {
		// 0.0.0.0/8 is never a destination: connect fails before sending.
		_, err := net.DialTimeout("tcp", "0.0.0.1:9", 5*time.Second)
		is(t, err, syscall.ENETUNREACH)
	})
	t.Run("oversized datagram", func(t *testing.T) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_, err = conn.WriteToUDP(make([]byte, 70000), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		is(t, err, syscall.EMSGSIZE)
	})
}
