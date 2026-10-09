package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// An invalid header and a real oversized IPv4 UDP write must be visible,
// while the next small datagram still travels on the same association.
func TestUDPRelayReportsLossWithoutEndingTheAssociation(t *testing.T) {
	native := newScriptedNative()
	counters := new(UDPRelayCounters)
	drops := make(chan string, 4)
	ended := make(chan *ConnEnd, 1)
	_, stream, served := nativeRequest(t, &Config{
		NativeUDP:        func(net.Conn) (NativeAssociation, error) { return native, nil },
		UDPRelayCounters: counters,
		OnUDPDrop:        func(reason string) { drops <- reason },
		OnConnEnd:        func(_ net.Conn, end *ConnEnd) { ended <- end },
	})
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	addr := &AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: target.LocalAddr().(*net.UDPAddr).Port}
	native.in <- scriptedDatagram{data: []byte{0}}
	body := BuildUDPHeader(addr, make([]byte, 65508))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
	frame = append(frame, body...)
	if _, err := stream.Write(frame); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]int)
	for range 2 {
		select {
		case reason := <-drops:
			seen[reason]++
		case <-time.After(3 * time.Second):
			t.Fatal("silent relay drop")
		}
	}
	if seen[UDPDropInvalidHeader] != 1 || seen[UDPDropTargetTooLarge] != 1 {
		t.Fatalf("drop reasons: %v", seen)
	}
	native.in <- scriptedDatagram{data: BuildUDPHeader(addr, []byte("voice packet"))}
	_ = target.SetDeadline(time.Now().Add(3 * time.Second))
	var buf [2048]byte
	n, peer, err := target.ReadFromUDPAddrPort(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.WriteToUDPAddrPort(buf[:n], peer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-native.sent:
	case <-time.After(3 * time.Second):
		t.Fatal("reply lost after target write failure")
	}
	_ = stream.Close()
	select {
	case <-served:
	case <-time.After(3 * time.Second):
		t.Fatal("association did not close")
	}
	want := UDPRelaySnapshot{ClientIn: 3, TargetOut: 1, TargetIn: 1, ClientOut: 1, Drops: 2, TargetWriteErrors: 1}
	if got := counters.Snapshot(); got != want {
		t.Fatalf("global stages: %+v, want %+v", got, want)
	}
	if got := (<-ended).UDPRelay; got != want {
		t.Fatalf("association stages: %+v, want %+v", got, want)
	}
}

func TestUDPReportsExposeAnIdlePeriodAndStopWithTheAssociation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		req := &Request{end: &ConnEnd{}}
		var periods []UDPRelaySnapshot
		s, err := New(&Config{UDPDiagnosticsInterval: time.Second,
			OnUDPReport: func(_ net.Conn, _ UDPRelaySnapshot, delta UDPRelaySnapshot) { periods = append(periods, delta) }})
		if err != nil {
			t.Fatal(err)
		}
		stop := s.startUDPReport(context.Background(), req, nil)
		s.udpClientIn(req)
		time.Sleep(time.Second)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		stop()
		time.Sleep(2 * time.Second)
		want := []UDPRelaySnapshot{{ClientIn: 1}, {}}
		if !reflect.DeepEqual(periods, want) {
			t.Fatalf("periods: %+v, want %+v", periods, want)
		}
	})
}

func TestTargetUDPWriteErrorsHaveClosedClasses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{net.ErrClosed, UDPDropTargetClosed}, {context.DeadlineExceeded, UDPDropTargetTimeout},
		{syscall.EMSGSIZE, UDPDropTargetTooLarge}, {syscall.ENOBUFS, UDPDropTargetNoBuffer},
		{syscall.ENETUNREACH, UDPDropTargetUnreachable}, {errors.New("target address secret"), UDPDropTargetOther},
	} {
		err := &net.OpError{Op: "write", Net: "udp", Addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}, Err: tc.err}
		if got := udpWriteFailure(err); got != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.want)
		}
	}
}

func TestFailedUDPResolutionCountsEachDiscardedPacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var failures atomic.Uint64
		d := newUDPDispatcher(context.Background(), func(context.Context, string) (net.IP, error) {
			return nil, errors.New("unavailable resolver")
		}, func([]byte, netip.AddrPort) bool { t.Error("unresolved packet sent"); return true }, func() {}, func(reason string) {
			if reason != UDPDropDNSFailed {
				t.Errorf("drop: %s", reason)
			}
			failures.Add(1)
		})
		for range 3 {
			d.submit(&AddrSpec{FQDN: "voice.invalid", Port: 5000}, []byte("packet"))
		}
		synctest.Wait()
		d.close()
		if failures.Load() != 3 {
			t.Fatalf("DNS failures: %d", failures.Load())
		}
	})
}
