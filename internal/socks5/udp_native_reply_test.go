package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// nativeRequest runs one 0x84 request through a server built from conf and
// returns the reply, the client's end of the connection and what the handler
// returned once the connection closes.
func nativeRequest(t *testing.T, conf *Config) ([]byte, net.Conn, <-chan error) {
	t.Helper()
	conf.BindIP = net.ParseIP("127.0.0.1")
	conf.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := New(conf)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		served <- server.ServeConnContext(context.Background(), c)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0, 5, UDPNativeCommand, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 12)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	return reply[2:], conn, served
}

func kindOf(err error) FailureKind {
	var ce *ConnError
	if errors.As(err, &ce) {
		return ce.Kind
	}
	return ""
}

// A server without native UDP answers 0x84 as a plain SOCKS5 server would:
// command not supported, which a client takes for "ask again by 0x83", and
// which is a protocol refusal rather than an internal error.
func TestAServerWithoutNativeUDPRefusesTheCommand(t *testing.T) {
	reply, conn, served := nativeRequest(t, &Config{})
	if reply[1] != commandNotSupported {
		t.Fatalf("reply %#x, want command not supported", reply[1])
	}
	_ = conn.Close()
	if err := <-served; kindOf(err) != FailureProtocol {
		t.Fatalf("the refusal is %q (%v), want %q", kindOf(err), err, FailureProtocol)
	}
}

// A connection that has no native path gets port 0, and the association goes
// on by 0x83 on the same connection: a client does not pay for a second one.
func TestAConnectionWithoutANativePathIsCarriedBy0x83(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var b [2048]byte
		for {
			n, peer, err := echo.ReadFromUDPAddrPort(b[:])
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(b[:n], peer)
		}
	}()
	reply, conn, _ := nativeRequest(t, &Config{
		NativeUDP: func(net.Conn) (NativeAssociation, error) { return nil, nil },
	})
	if reply[1] != successReply || binary.BigEndian.Uint16(reply[8:]) != 0 {
		t.Fatalf("reply %x, want success with port 0", reply)
	}
	body := BuildUDPHeader(&AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, []byte("tick"))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
	if _, err := conn.Write(append(frame, body...)); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatalf("the answer by 0x83: %v", err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, answer); err != nil || !strings.HasSuffix(string(answer), "tick") {
		t.Fatalf("answer %q, %v", answer, err)
	}
}

// A hook that fails is the server's failure, and says why. It used to be
// command not supported with "%!w(<nil>)" in the error, counted as internal.
func TestANativeHookThatFailsIsAServerFailure(t *testing.T) {
	cause := errors.New("no keys for this listener")
	reply, conn, served := nativeRequest(t, &Config{
		NativeUDP: func(net.Conn) (NativeAssociation, error) { return nil, cause },
	})
	if reply[1] != serverFailure {
		t.Fatalf("reply %#x, want server failure", reply[1])
	}
	_ = conn.Close()
	if err := <-served; !errors.Is(err, cause) || strings.Contains(err.Error(), "%!") {
		t.Fatalf("the failure is %v, want the hook's error", err)
	}
}

// scriptedNative is a native path whose Send fails as scripted: call i
// returns errs[i], and a call past the script succeeds.
type scriptedNative struct {
	in       chan []byte
	heard    chan struct{}
	sent     chan []byte
	resynced chan uint64
	next     atomic.Uint64
	errs     []error
	calls    atomic.Int32
}

func newScriptedNative(errs ...error) *scriptedNative {
	return &scriptedNative{in: make(chan []byte, 1), heard: make(chan struct{}, 1), sent: make(chan []byte, 8),
		resynced: make(chan uint64, 8), errs: errs}
}

func (f *scriptedNative) Port() int          { return 40000 }
func (f *scriptedNative) MaxPayload() int    { return 1300 }
func (f *scriptedNative) Close()             {}
func (f *scriptedNative) Resync(next uint64) { f.resynced <- next }
func (f *scriptedNative) Next() uint64       { return f.next.Load() }
func (f *scriptedNative) Receive(ctx context.Context, datagram func([]byte), heard func()) bool {
	select {
	case <-ctx.Done():
		return false
	case <-f.heard:
		heard()
		return true
	case p := <-f.in:
		datagram(p)
		return true
	}
}
func (f *scriptedNative) Send(b []byte) error {
	if i := int(f.calls.Add(1)) - 1; i < len(f.errs) && f.errs[i] != nil {
		return f.errs[i]
	}
	f.sent <- append([]byte(nil), b...)
	return nil
}

// nativeAnswers opens a 0x84 association over native, sends one datagram
// native to a target and returns the target, the address the server writes
// to it from and the client's control connection.
func nativeAnswers(t *testing.T, native *scriptedNative) (*net.UDPConn, netip.AddrPort, net.Conn) {
	t.Helper()
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	reply, conn, _ := nativeRequest(t, &Config{
		NativeUDP: func(net.Conn) (NativeAssociation, error) { return native, nil },
	})
	if reply[1] != successReply {
		t.Fatalf("reply %x, want success", reply)
	}
	native.in <- BuildUDPHeader(&AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: target.LocalAddr().(*net.UDPAddr).Port}, []byte("hello"))
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [2048]byte
	_, relay, err := target.ReadFromUDPAddrPort(b[:])
	if err != nil {
		t.Fatalf("the native datagram did not reach the target: %v", err)
	}
	return target, relay, conn
}

func readTCPAnswer(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		t.Fatalf("no answer by TCP: %v", err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

// One answer the native socket fails to write (ENOBUFS, say) goes by the
// control connection, and the next one goes native again. It used to take
// every answer after it to TCP until the client's next native datagram,
// which from an application that only listens never comes (decision 18 of
// docs/plan/native-udp-review.md).
func TestOneFailedNativeAnswerGoesByTCPAndTheNextGoesNative(t *testing.T) {
	native := newScriptedNative(errors.New("write udp: no buffer space available"))
	target, relay, conn := nativeAnswers(t, native)

	if _, err := target.WriteToUDPAddrPort([]byte("one"), relay); err != nil {
		t.Fatal(err)
	}
	if answer := readTCPAnswer(t, conn); !strings.HasSuffix(string(answer), "one") {
		t.Fatalf("TCP answer %q, want the one native failed to carry", answer)
	}
	if _, err := target.WriteToUDPAddrPort([]byte("two"), relay); err != nil {
		t.Fatal(err)
	}
	select {
	case answer := <-native.sent:
		if !strings.HasSuffix(string(answer), "two") {
			t.Fatalf("native answer %q", answer)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the answer after one failed write did not go native")
	}
}

// A path that is gone takes the answers to TCP and keeps them there: the
// server does not try a closed association once per datagram.
func TestAGoneNativePathKeepsTheAnswersOnTCP(t *testing.T) {
	native := newScriptedNative(fmt.Errorf("session removed: %w", ErrNativePathGone))
	target, relay, conn := nativeAnswers(t, native)

	for _, word := range []string{"one", "two"} {
		if _, err := target.WriteToUDPAddrPort([]byte(word), relay); err != nil {
			t.Fatal(err)
		}
		if answer := readTCPAnswer(t, conn); !strings.HasSuffix(string(answer), word) {
			t.Fatalf("TCP answer %q, want %q", answer, word)
		}
	}
	if calls := native.calls.Load(); calls != 1 {
		t.Fatalf("Send called %d times, want once: the path was gone after the first", calls)
	}
	select {
	case answer := <-native.sent:
		t.Fatalf("answer %q went native after the path was gone", answer)
	default:
	}
}

// The client's empty frame carries the counter of its next native datagram,
// and the server answers it on the stream with the counter of its own: past
// a window of datagrams lost in a row neither side would recognise the
// other's again (finding 3 of review 3 in docs/plan/native-udp-review.md).
// The answers after it go by TCP.
func TestTheEmptyFrameCarriesTheCountersBothWays(t *testing.T) {
	native := newScriptedNative()
	native.next.Store(7000)
	target, relay, conn := nativeAnswers(t, native)

	frame := binary.BigEndian.AppendUint64([]byte{0, 0}, 5000)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case next := <-native.resynced:
		if next != 5000 {
			t.Fatalf("resynced to %d, want 5000", next)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the client's counter did not reach the native path")
	}
	var answer [10]byte
	if _, err := io.ReadFull(conn, answer[:]); err != nil {
		t.Fatalf("no answer to the empty frame: %v", err)
	}
	if length, next := binary.BigEndian.Uint16(answer[:2]), binary.BigEndian.Uint64(answer[2:]); length != 0 || next != 7000 {
		t.Fatalf("answer %x, want an empty frame with 7000", answer)
	}
	if _, err := target.WriteToUDPAddrPort([]byte("one"), relay); err != nil {
		t.Fatal(err)
	}
	if answer := readTCPAnswer(t, conn); !strings.HasSuffix(string(answer), "one") {
		t.Fatalf("TCP answer %q", answer)
	}
}
