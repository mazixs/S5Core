package s5server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/veil"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestNativeUDPAndTCPFallbackShareAnAssociation(t *testing.T) {
	plainPort, obfsPort := reservePort(t), reservePort(t)
	srv := startServer(t, Config{
		Port: plainPort, ListenIP: "127.0.0.1", RequireAuth: false,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		ObfsEnabled: true, ObfsPort: obfsPort, ObfsPSK: testPSK,
		ObfsMaxPadding: 32, ObfsMTU: 1400, UDPPort: reserveUDPPort(t),
	})
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

	stream, err := dialObfs(t, "127.0.0.1:"+obfsPort)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if code := socksOver(t, stream, socks5.UDPNativeCommand, []byte{1, 0, 0, 0, 0, 0, 0}); code != 0 {
		t.Fatalf("native reply code %d", code)
	}
	_ = stream.SetDeadline(time.Time{})
	keys, err := obfs.DatagramKeysOf(stream)
	if err != nil {
		t.Fatal(err)
	}
	client := nativeudp.NewSession(keys)
	hub := srv.nativeHub.Load()
	if hub == nil {
		t.Fatal("native hub missing")
	}
	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	wire, err := client.Seal(nil, nativeudp.KindProbe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	var b [2048]byte
	n, err := udp.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err := client.Open(b[:n])
	if err != nil || p.Kind != nativeudp.KindProbeAck {
		t.Fatalf("probe: %v %+v", err, p)
	}
	body := socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, []byte("game tick"))
	wire, err = client.Seal(nil, nativeudp.KindData, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	n, err = udp.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	p, err = client.Open(b[:n])
	if err != nil || p.Kind != nativeudp.KindData || !bytes.HasSuffix(p.Data, []byte("game tick")) {
		t.Fatalf("native response: %v %+v", err, p)
	}
	// A datagram by 0x83 on the same association reaches its target, and the
	// answer stays native: the client sends by 0x83 what is too big for
	// native, and the answers used to follow it to TCP for as long as the
	// client sent nothing native (finding 1 of the third review).
	body = socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: echo.LocalAddr().(*net.UDPAddr).Port}, []byte("by 0x83"))
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(body)))
	copy(frame[2:], body)
	if _, err := stream.Write(frame); err != nil {
		t.Fatal(err)
	}
	_ = udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = udp.Read(b[:])
	if err != nil {
		t.Fatalf("the answer to a datagram by 0x83 did not come native: %v", err)
	}
	if p, err = client.Open(b[:n]); err != nil || p.Kind != nativeudp.KindData || !bytes.HasSuffix(p.Data, []byte("by 0x83")) {
		t.Fatalf("native answer: %v %+v", err, p)
	}
}

func TestNativeUDPMetricsHaveOnlyFixedOutcomes(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	hub, err := nativeudp.Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	registration, err := registerNativeMetrics(tel, hub)
	if err != nil {
		t.Fatal(err)
	}
	defer registration.Unregister()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "s5core_native_udp_packets_total":
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok || len(sum.DataPoints) != 5 {
					t.Fatalf("packet metric: %T %+v", m.Data, m.Data)
				}
				for _, p := range sum.DataPoints {
					if p.Attributes.Len() != 1 || p.Value != 0 {
						t.Fatalf("packet labels or value: %+v", p)
					}
					value, ok := p.Attributes.Value("outcome")
					if !ok {
						t.Fatalf("missing outcome: %+v", p)
					}
					seen[value.AsString()] = true
				}
			case "s5core_native_udp_sessions":
				gauge, ok := m.Data.(metricdata.Gauge[int64])
				if !ok || len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Attributes.Len() != 0 {
					t.Fatalf("sessions metric: %T %+v", m.Data, m.Data)
				}
			}
		}
	}
	for _, label := range []string{"accepted", "tag", "replay", "auth", "read_error"} {
		if !seen[label] {
			t.Fatalf("outcome %q missing: %+v", label, seen)
		}
	}
}

// nativeFixture is one 0x84 association on a server with native UDP, and a
// target that has heard from it natively once, so the target knows where to
// answer.
type nativeFixture struct {
	stream net.Conn
	client *nativeudp.Session
	udp    *net.UDPConn
	target *net.UDPConn
	relay  netip.AddrPort
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	plainPort, obfsPort := reservePort(t), reservePort(t)
	srv := startServer(t, Config{
		Port: plainPort, ListenIP: "127.0.0.1", RequireAuth: false,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
		ObfsEnabled: true, ObfsPort: obfsPort, ObfsPSK: testPSK,
		ObfsMaxPadding: 32, ObfsMTU: 1400, UDPPort: reserveUDPPort(t),
	})
	f := &nativeFixture{}
	var err error
	if f.target, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.target.Close() })
	if f.stream, err = dialObfs(t, "127.0.0.1:"+obfsPort); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.stream.Close() })
	if code := socksOver(t, f.stream, socks5.UDPNativeCommand, []byte{1, 0, 0, 0, 0, 0, 0}); code != 0 {
		t.Fatalf("native reply code %d", code)
	}
	_ = f.stream.SetDeadline(time.Time{})
	keys, err := obfs.DatagramKeysOf(f.stream)
	if err != nil {
		t.Fatal(err)
	}
	f.client = nativeudp.NewSession(keys)
	if f.udp, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: srv.nativeHub.Load().Port()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.udp.Close() })

	f.send(t, nativeudp.KindData, socks5.BuildUDPHeader(&socks5.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: f.target.LocalAddr().(*net.UDPAddr).Port}, []byte("hello")))
	_ = f.target.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [2048]byte
	if _, f.relay, err = f.target.ReadFromUDPAddrPort(b[:]); err != nil {
		t.Fatalf("the datagram did not reach the target: %v", err)
	}
	return f
}

func (f *nativeFixture) send(t *testing.T, kind byte, payload []byte) {
	t.Helper()
	wire, err := f.client.Seal(nil, kind, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.udp.Write(wire); err != nil {
		t.Fatal(err)
	}
}

// signal is the client's empty frame: it does not hear the server natively,
// and this is the counter of its next datagram. The server answers with the
// counter of its own, which the client takes as a real one does.
func (f *nativeFixture) signal(t *testing.T) {
	t.Helper()
	if _, err := f.stream.Write(binary.BigEndian.AppendUint64([]byte{0, 0}, f.client.Next())); err != nil {
		t.Fatal(err)
	}
	_ = f.stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var length [2]byte
		if _, err := io.ReadFull(f.stream, length[:]); err != nil {
			t.Fatalf("no answer to the empty frame: %v", err)
		}
		if n := binary.BigEndian.Uint16(length[:]); n != 0 {
			if _, err := io.CopyN(io.Discard, f.stream, int64(n)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		var next [8]byte
		if _, err := io.ReadFull(f.stream, next[:]); err != nil {
			t.Fatal(err)
		}
		f.client.Resync(binary.BigEndian.Uint64(next[:]))
		return
	}
}

// native reads the next packet of the given kind the server sends natively.
func (f *nativeFixture) native(t *testing.T, kind byte) (nativeudp.Packet, error) {
	t.Helper()
	var b [2048]byte
	_ = f.udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		n, err := f.udp.Read(b[:])
		if err != nil {
			return nativeudp.Packet{}, err
		}
		if p, err := f.client.Open(b[:n]); err == nil && p.Kind == kind {
			return p, nil
		}
	}
}

// byTCP has the target answer every 20 ms until one answer comes by the
// control connection, and returns it: a frame on the connection and the
// target's datagrams race inside the server.
func (f *nativeFixture) byTCP(t *testing.T, word string) []byte {
	t.Helper()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_, _ = f.target.WriteToUDPAddrPort([]byte(word), f.relay)
			}
		}
	}()
	_ = f.stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(f.stream, length[:]); err != nil {
		t.Fatalf("no answer by TCP: %v", err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(f.stream, answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

// The client says it does not hear the server natively with a frame of zero
// length on the control connection. It has to be a frame of its own: an
// application that only listens sends no datagram that could carry the news,
// and the server would go on answering into a path nobody hears (finding 1 of
// the 2.3 review).
func TestAnEmptyFrameMovesTheAnswersToTCP(t *testing.T) {
	f := newNativeFixture(t)
	if _, err := f.target.WriteToUDPAddrPort([]byte("native"), f.relay); err != nil {
		t.Fatal(err)
	}
	if p, err := f.native(t, nativeudp.KindData); err != nil || !bytes.HasSuffix(p.Data, []byte("native")) {
		t.Fatalf("native answer: %v %+v", err, p)
	}
	f.signal(t)
	if answer := f.byTCP(t, "by tcp"); !bytes.HasSuffix(answer, []byte("by tcp")) {
		t.Fatalf("TCP answer %x", answer)
	}
}

// Past a window of datagrams lost in a row in either direction neither side
// recognises the other's again, and the path would stay dead until a new
// association. The empty frame carries the client's next counter and its
// answer the server's, and the path comes back (finding 3 of review 3 in
// docs/plan/native-udp-review.md).
func TestTheCountersResyncAfterMoreLostThanTheWindow(t *testing.T) {
	f := newNativeFixture(t)
	const lost = 1200
	for i := 0; i < lost; i++ {
		if _, err := f.client.Seal(nil, nativeudp.KindData, nil); err != nil {
			t.Fatal(err)
		}
	}
	// The server's answers reach the client's socket and not its window.
	drained := make(chan int)
	go func() {
		var b [2048]byte
		got := 0
		for {
			_ = f.udp.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if _, err := f.udp.Read(b[:]); err != nil {
				drained <- got
				return
			}
			got++
		}
	}()
	for i := 0; i < lost; i++ {
		if _, err := f.target.WriteToUDPAddrPort([]byte("unheard"), f.relay); err != nil {
			t.Fatal(err)
		}
		if i%50 == 49 {
			time.Sleep(time.Millisecond)
		}
	}
	if got := <-drained; got < 600 {
		t.Fatalf("only %d of %d answers went native; the window was not passed", got, lost)
	}

	f.signal(t)
	f.send(t, nativeudp.KindProbe, []byte{nativeudp.ProbeHeard})
	if _, err := f.native(t, nativeudp.KindProbeAck); err != nil {
		t.Fatalf("the probe after the resync was not answered: %v", err)
	}
	if _, err := f.target.WriteToUDPAddrPort([]byte("back"), f.relay); err != nil {
		t.Fatal(err)
	}
	if p, err := f.native(t, nativeudp.KindData); err != nil || !bytes.HasSuffix(p.Data, []byte("back")) {
		t.Fatalf("native answer after the resync: %v %+v", err, p)
	}
}

// Once the client has said it does not hear the server, only a probe saying
// it hears it again brings the answers back native. A bare probe does not:
// the client probes the path it lost, and the probe arrives right after the
// signal, while the answers would still go nowhere. An application that only
// listens has no datagram to bring them back, so without the heard probe it
// stayed on TCP until the association ended (finding 2 of the third review).
func TestOnlyAProbeThatHearsTheServerBringsTheAnswersBack(t *testing.T) {
	f := newNativeFixture(t)
	f.signal(t)
	f.byTCP(t, "lost")

	f.send(t, nativeudp.KindProbe, nil)
	if _, err := f.native(t, nativeudp.KindProbeAck); err != nil {
		t.Fatalf("no answer to the bare probe: %v", err)
	}
	if answer := f.byTCP(t, "after bare"); !bytes.HasSuffix(answer, []byte("after bare")) {
		t.Fatalf("TCP answer %q after a bare probe", answer)
	}

	f.send(t, nativeudp.KindProbe, []byte{nativeudp.ProbeHeard})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
				_, _ = f.target.WriteToUDPAddrPort([]byte("heard"), f.relay)
			}
		}
	}()
	if p, err := f.native(t, nativeudp.KindData); err != nil || !bytes.HasSuffix(p.Data, []byte("heard")) {
		t.Fatalf("the answers did not come back native after a heard probe: %v %+v", err, p)
	}
}

// The relay takes the answers to TCP for good only when the path is gone
// (decision 18 of docs/plan/native-udp-review.md): a session with no peer
// yet, a removed one, a closed hub. One failed write is not that.
func TestANativeSendSaysWhenThePathIsGone(t *testing.T) {
	psk, secret := bytes.Repeat([]byte{7}, 32), []byte("secret")
	serverKeys, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := veil.DeriveDatagram(psk, secret, veil.Context{}, veil.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := nativeudp.Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	a := &nativeAssociation{hub: hub, session: hub.Register(serverKeys)}
	gone := func(stage string, err error, cause error) {
		t.Helper()
		if !errors.Is(err, socks5.ErrNativePathGone) || !errors.Is(err, cause) {
			t.Fatalf("%s: %v, want the path gone because of %v", stage, err, cause)
		}
	}
	gone("no peer yet", a.Send([]byte("x")), nativeudp.ErrPacket)

	udp, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	client := nativeudp.NewSession(clientKeys)
	wire, err := client.Seal(nil, nativeudp.KindProbe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	var b [2048]byte
	if _, err := udp.Read(b[:]); err != nil {
		t.Fatalf("no probe ack: %v", err)
	}
	if err := a.Send([]byte("x")); err != nil {
		t.Fatalf("a session with a peer: %v", err)
	}

	_ = hub.Close()
	gone("closed hub", a.Send([]byte("x")), net.ErrClosed)
	a.Close()
	gone("removed session", a.Send([]byte("x")), nativeudp.ErrPacket)

	enobufs := &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmsg", syscall.ENOBUFS)}
	if err := nativeSendError(enobufs); !errors.Is(err, syscall.ENOBUFS) || errors.Is(err, socks5.ErrNativePathGone) {
		t.Fatalf("one failed write came back as %v, want it without the path gone", err)
	}
	if err := nativeSendError(nil); err != nil {
		t.Fatalf("no error came back as %v", err)
	}
}

// socksOver runs the no-auth greeting and one request over c and returns the
// reply code.
func socksOver(t *testing.T, c net.Conn, command byte, addr []byte) byte {
	t.Helper()
	if _, err := c.Write(append([]byte{0x05, 0x01, 0x00, 0x05, command, 0x00}, addr...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 12)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	return reply[3]
}
