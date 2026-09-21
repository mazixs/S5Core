package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A UDP association used to be accounted for by nobody: neither mode asked
// whether the account behind it could still transfer, the 0x83 mode counted no
// traffic at all, and the counting the RFC 1928 mode did went through the
// metrics hooks, so a deployment without telemetry billed nothing.
//
// Finding F03 of docs/reports/code-quality-audit-2026-09-20.md.

// loopbackResolver answers every name with the loopback address, so a test
// can send the same bytes to the same socket under two spellings of its
// destination.
type loopbackResolver struct{}

func (loopbackResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, net.ParseIP("127.0.0.1"), nil
}

// meteredStand is a SOCKS5 server that meters one account, with no telemetry
// configured - which is the configuration the accounting must not depend on.
type meteredStand struct {
	addr    string
	counter *atomic.Int64
	status  atomic.Int32 // SessionStatus
	echo    *net.UDPConn
	// asked counts how many times the account was consulted.
	asked atomic.Int32
}

func newMeteredStand(t *testing.T) *meteredStand {
	t.Helper()
	stand := &meteredStand{counter: new(atomic.Int64)}
	stand.status.Store(int32(SessionAllowed))

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	stand.echo = echo
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], from)
		}
	}()

	conf := &Config{
		BindIP:   net.ParseIP("127.0.0.1"),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Resolver: loopbackResolver{},
		AuthMethods: []Authenticator{UserPassAuthenticator{
			Credentials: StaticCredentials{"metered": "secret"},
		}},
		TrafficCounter: func(username string) *atomic.Int64 {
			if username != "metered" {
				return nil
			}
			return stand.counter
		},
		SessionStatus: func(string) SessionStatus {
			stand.asked.Add(1)
			return SessionStatus(stand.status.Load())
		},
		// No telemetry: BytesAddIn and BytesAddOut stay nil on purpose.
	}
	server, err := New(conf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() { _ = server.ServeContext(ctx, ln) }()
	stand.addr = ln.Addr().String()
	return stand
}

func (s *meteredStand) echoSpec() *AddrSpec {
	a := s.echo.LocalAddr().(*net.UDPAddr)
	return &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: a.Port}
}

// associateAs authenticates and opens an association, returning the TCP
// connection and the address the client was told to send to.
func (s *meteredStand) associateAs(t *testing.T, command byte) (net.Conn, *net.UDPAddr) {
	t.Helper()
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if greeting[1] != 0x02 {
		t.Fatalf("server chose auth method 0x%02x, want user/password", greeting[1])
	}
	auth := []byte{0x01, 7}
	auth = append(auth, "metered"...)
	auth = append(auth, 6)
	auth = append(auth, "secret"...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("auth: %v", err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if authReply[1] != 0 {
		t.Fatalf("authentication refused: 0x%02x", authReply[1])
	}

	req := []byte{0x05, command, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("associate: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("associate reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("associate refused: 0x%02x", reply[1])
	}
	return conn, &net.UDPAddr{
		IP:   net.IPv4(reply[4], reply[5], reply[6], reply[7]),
		Port: int(reply[8])<<8 | int(reply[9]),
	}
}

// eventually waits for a condition that a background goroutine brings about.
func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The payload is billed, and it is billed once per direction. The SOCKS5 UDP
// header is not: its size depends on how the destination was spelled, so
// billing it would make the same transfer cost different amounts of quota.
func TestAUDPAssociationBillsItsPayloadAndNothingElse(t *testing.T) {
	const payload = 300

	t.Run("associate", func(t *testing.T) {
		stand := newMeteredStand(t)
		conn, proxy := stand.associateAs(t, AssociateCommand)

		client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("client socket: %v", err)
		}
		defer func() { _ = client.Close() }()

		msg := make([]byte, payload)
		for i := range msg {
			msg[i] = byte(i)
		}
		if _, err := client.WriteToUDP(BuildUDPHeader(stand.echoSpec(), msg), proxy); err != nil {
			t.Fatalf("send: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65535)
		if _, _, err := client.ReadFromUDP(buf); err != nil {
			t.Fatalf("no echo came back: %v", err)
		}

		// Closing the TCP connection ends the association, and both halves
		// flush what they have not reported yet. Nothing below the batch size
		// may be lost, which is what this waits for.
		_ = conn.Close()
		eventually(t, 3*time.Second, "the association to report its traffic", func() bool {
			return stand.counter.Load() >= 2*payload
		})
		time.Sleep(200 * time.Millisecond)
		if got := stand.counter.Load(); got != 2*payload {
			t.Fatalf("the account was billed %d bytes for %d in and %d out; "+
				"headers or a double count are in there", got, payload, payload)
		}
	})

	t.Run("tunnelled", func(t *testing.T) {
		stand := newMeteredStand(t)
		conn, _ := stand.associateAs(t, UDPTunnelCommand)

		msg := make([]byte, payload)
		body := BuildUDPHeader(stand.echoSpec(), msg)
		frame := make([]byte, 2+len(body))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
		copy(frame[2:], body)
		if _, err := conn.Write(frame); err != nil {
			t.Fatalf("write frame: %v", err)
		}

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			t.Fatalf("no echo came back: %v", err)
		}
		reply := make([]byte, binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("reply body: %v", err)
		}

		_ = conn.Close()
		eventually(t, 3*time.Second, "the tunnel to report its traffic", func() bool {
			return stand.counter.Load() >= 2*payload
		})
		time.Sleep(200 * time.Millisecond)
		if got := stand.counter.Load(); got != 2*payload {
			t.Fatalf("the account was billed %d bytes for %d in and %d out; "+
				"the length prefix or the header is in there", got, payload, payload)
		}
	})
}

// The destination spelled as a name carries a longer header than the same
// destination spelled as an address. The bill is the same, which is the
// property the rule "payload only" exists for.
func TestHowTheDestinationIsSpelledDoesNotChangeTheBill(t *testing.T) {
	const payload = 100
	bills := map[string]int64{}

	for _, spelling := range []string{"address", "name"} {
		stand := newMeteredStand(t)
		port := stand.echo.LocalAddr().(*net.UDPAddr).Port
		dest := stand.echoSpec()
		if spelling == "name" {
			dest = &AddrSpec{FQDN: "a-rather-long-name-for-the-echo.example.com", Port: port}
		}
		// The name resolves to the echo server, so both runs move the same
		// bytes between the same two sockets.
		conn, proxy := stand.associateAs(t, AssociateCommand)

		client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("client socket: %v", err)
		}
		if _, err := client.WriteToUDP(BuildUDPHeader(dest, make([]byte, payload)), proxy); err != nil {
			t.Fatalf("send: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65535)
		if _, _, err := client.ReadFromUDP(buf); err != nil {
			t.Fatalf("%s: no echo came back: %v", spelling, err)
		}
		_ = conn.Close()
		_ = client.Close()
		eventually(t, 3*time.Second, "the association to report its traffic", func() bool {
			return stand.counter.Load() >= 2*payload
		})
		bills[spelling] = stand.counter.Load()
	}

	if bills["address"] != bills["name"] {
		t.Fatalf("the same transfer cost %d bytes by address and %d by name",
			bills["address"], bills["name"])
	}
}

// An association outlived its account: the quota could run out, the account
// could expire or be deleted, and the datagrams kept flowing until the client
// chose to stop. The account is asked on the same boundary the TCP relay uses
// it on, and the association ends when the answer is no.
func TestAnAssociationEndsWhenItsAccountSaysStop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command byte
		status  SessionStatus
	}{
		{"associate out of quota", AssociateCommand, SessionQuotaExceeded},
		{"associate expired", AssociateCommand, SessionExpired},
		{"tunnelled out of quota", UDPTunnelCommand, SessionQuotaExceeded},
		{"tunnelled expired", UDPTunnelCommand, SessionExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stand := newMeteredStand(t)
			conn, proxy := stand.associateAs(t, tc.command)

			client, err := net.ListenUDP("udp",
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
			if err != nil {
				t.Fatalf("client socket: %v", err)
			}
			defer func() { _ = client.Close() }()

			send := func() error {
				body := BuildUDPHeader(stand.echoSpec(), make([]byte, 100))
				if tc.command != UDPTunnelCommand {
					_, err := client.WriteToUDP(body, proxy)
					return err
				}
				frame := make([]byte, 2+len(body))
				binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
				copy(frame[2:], body)
				_, err := conn.Write(frame)
				return err
			}
			// receive waits for one echo to come back the way this mode
			// carries it.
			receive := func(within time.Duration) error {
				if tc.command != UDPTunnelCommand {
					_ = client.SetReadDeadline(time.Now().Add(within))
					buf := make([]byte, 65535)
					_, _, err := client.ReadFromUDP(buf)
					return err
				}
				_ = conn.SetReadDeadline(time.Now().Add(within))
				lenBuf := make([]byte, 2)
				if _, err := io.ReadFull(conn, lenBuf); err != nil {
					return err
				}
				_, err := io.ReadFull(conn, make([]byte, binary.BigEndian.Uint16(lenBuf)))
				return err
			}

			// One round trip while the account is in good standing, so the
			// association is known to work before anything is taken away.
			if err := send(); err != nil {
				t.Fatalf("send: %v", err)
			}
			if err := receive(3 * time.Second); err != nil {
				t.Fatalf("the association did not work to begin with: %v", err)
			}

			stand.status.Store(int32(tc.status))

			// An association that ends closes the TCP connection that opened
			// it. Under RFC 1928 that connection carries nothing, so its
			// close is the only signal the client gets; the tunnel carries
			// its datagrams there and sees the same close as a failed write.
			tcpDead := make(chan struct{})
			if tc.command != UDPTunnelCommand {
				go func() {
					_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
					if _, err := conn.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
						close(tcpDead)
					}
				}()
			}

			// The account is consulted once the batch is due, and a barely
			// used association reaches that by time rather than by volume -
			// which is the case that matters here, because a byte threshold
			// alone would take hours to reach at this rate.
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-tcpDead:
					return // the server ended the association
				default:
				}
				if err := send(); err != nil {
					// The tunnel carries its datagrams over the very
					// connection the server closed.
					return
				}
				if err := receive(300 * time.Millisecond); err != nil {
					if isTimeout(err) {
						continue // the datagram is simply not back yet
					}
					return // the server closed the association
				}
			}
			t.Fatal("the association outlived the account that paid for it")
		})
	}
}

// The account is not asked per datagram - that would be a lookup under a lock
// on the hot path - and it is not asked only per 64 KiB either, because a
// forwarder moving 60 bytes a query would reach that boundary hours later. The
// meter is where both bounds live, so this checks them directly.
func TestTheMeterAsksTheAccountOnBothItsBoundaries(t *testing.T) {
	newMeter := func(status SessionStatus) (*udpMeter, *atomic.Int64, *int) {
		asked := 0
		counter := new(atomic.Int64)
		acct := &udpAccount{
			counter: counter,
			status: func() SessionStatus {
				asked++
				return status
			},
		}
		return newUDPMeter(acct), counter, &asked
	}

	t.Run("a small transfer is not charged for a question", func(t *testing.T) {
		meter, counter, asked := newMeter(SessionAllowed)
		for range 100 {
			if st := meter.inbound(100); st != SessionAllowed {
				t.Fatalf("unexpected status %v", st)
			}
		}
		if *asked != 0 {
			t.Errorf("the account was asked %d times about 10 KiB", *asked)
		}
		if got := counter.Load(); got != 0 {
			t.Errorf("the counter was touched %d times below the batch", got)
		}
		// And nothing is lost: what was not reported is reported at the end.
		meter.flush()
		if got := counter.Load(); got != 10000 {
			t.Errorf("the final flush reported %d bytes, want 10000", got)
		}
	})

	t.Run("the batch boundary asks", func(t *testing.T) {
		meter, counter, asked := newMeter(SessionAllowed)
		meter.inbound(udpMeterBatch)
		if *asked != 1 {
			t.Errorf("the account was asked %d times at the batch boundary, want 1", *asked)
		}
		if got := counter.Load(); got != udpMeterBatch {
			t.Errorf("the counter holds %d bytes, want %d", got, udpMeterBatch)
		}
	})

	t.Run("time asks too", func(t *testing.T) {
		meter, _, asked := newMeter(SessionAllowed)
		meter.inbound(1)
		if *asked != 0 {
			t.Fatalf("one byte asked the account %d times", *asked)
		}
		// The association has been all but idle since the last question.
		meter.asked = time.Now().Add(-2 * udpStatusInterval)
		meter.inbound(1)
		if *asked != 1 {
			t.Errorf("an idle association asked the account %d times, want 1", *asked)
		}
	})

	t.Run("a refusal is passed on", func(t *testing.T) {
		meter, _, _ := newMeter(SessionExpired)
		if st := meter.inbound(udpMeterBatch); st != SessionExpired {
			t.Errorf("the meter answered %v, want the account's own answer", st)
		}
	})

	t.Run("no account is not a refusal", func(t *testing.T) {
		meter := newUDPMeter(&udpAccount{})
		if st := meter.inbound(udpMeterBatch); st != SessionAllowed {
			t.Errorf("a server that meters nobody refused with %v", st)
		}
		meter.flush() // must not panic on a nil counter
	})
}
