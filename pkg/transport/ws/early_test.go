package ws

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
)

// hijackSpy reports how many bytes net/http had buffered behind the request
// when the connection was taken over: the bytes gorilla refuses on its own.
type hijackSpy struct {
	http.ResponseWriter
	buffered chan int
}

func (s hijackSpy) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := s.ResponseWriter.(http.Hijacker).Hijack()
	if err == nil {
		s.buffered <- brw.Reader.Buffered()
	}
	return c, brw, err
}

type echoStand struct {
	url      string
	addr     string
	upgraded <-chan error
	accepted <-chan *Conn
	buffered <-chan int
}

// earlyEcho is a WebSocket echo server. It upgrades once release is closed:
// a test closes it when the client has written what it sends early.
func earlyEcho(t *testing.T, earlyData bool, release <-chan struct{}) echoStand {
	t.Helper()
	up := NewUpgrader(UpgraderOpts{Path: "/ws", EarlyData: earlyData})
	verdicts := make(chan error, 4)
	conns := make(chan *Conn, 4)
	buffered := make(chan int, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		c, err := up.Upgrade(hijackSpy{ResponseWriter: w, buffered: buffered}, r)
		verdicts <- err
		if err != nil {
			return
		}
		conns <- c
		go func() {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}()
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return echoStand{url: "ws://" + addr + "/ws", addr: addr, upgraded: verdicts, accepted: conns, buffered: buffered}
}

func released() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// upgradeWithFrame writes an upgrade request and one masked frame of p in a
// single write, so that the frame is in net/http's buffer with the request.
func upgradeWithFrame(t *testing.T, addr string, p []byte) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	req := "GET /ws HTTP/1.1\r\nHost: " + addr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := c.Write(append([]byte(req), maskedFrame(p)...)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c, bufio.NewReader(c)
}

// readServerFrame reads one final, unmasked, binary server frame.
func readServerFrame(r *bufio.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0x82 || h[1]&0x80 != 0 {
		return nil, errors.New("not a final unmasked binary frame")
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		n = int(binary.BigEndian.Uint16(b[:]))
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func TestTheServerTakesFramesSentBeforeItsAnswer(t *testing.T) {
	stand := earlyEcho(t, true, released())
	msg := payload(1000)
	_, br := upgradeWithFrame(t, stand.addr, msg)

	if n := <-stand.buffered; n == 0 {
		t.Fatal("the frame was not buffered with the request: the test did not reach the early path")
	}
	if err := <-stand.upgraded; err != nil {
		t.Fatalf("the upgrader refused early frames: %v", err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("answer %v, %v", resp, err)
	}
	var got []byte
	for len(got) < len(msg) {
		p, err := readServerFrame(br)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p...)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("the echo differs from what was sent early")
	}
	if _, ok := socketUnder(<-stand.accepted).(*net.TCPConn); !ok {
		t.Error("the server's socket is not reachable through NetConn")
	}
}

func TestWithoutEarlyDataTheServerRefusesFramesSentBeforeItsAnswer(t *testing.T) {
	stand := earlyEcho(t, false, released())
	_, br := upgradeWithFrame(t, stand.addr, payload(200))

	if n := <-stand.buffered; n == 0 {
		t.Fatal("the frame was not buffered with the request: the test did not reach the early path")
	}
	if err := <-stand.upgraded; err == nil || !strings.Contains(err.Error(), "before handshake") {
		t.Fatalf("the upgrader said %v, want gorilla's refusal of early data", err)
	}
	if resp, err := http.ReadResponse(br, nil); err == nil {
		t.Fatalf("the refused connection was answered with %d", resp.StatusCode)
	}
}

// The client half: what it writes before the answer reaches the server, and
// the answer reaches what it reads.
func TestAnEarlyDialWritesBeforeTheAnswer(t *testing.T) {
	release := make(chan struct{})
	stand := earlyEcho(t, true, release)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	c, err := DialEarly(ctx, DialOpts{URL: stand.url}, Shape{MinFrame: 256, MaxFrame: 1024})
	// The caller's context ends with the dial, as dialServer's does: the
	// upgrade in flight must not end with it.
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	msg := payload(3000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-stand.upgraded; err != nil {
		t.Fatalf("the upgrader refused early frames: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("the echo differs from what was sent early")
	}
	if _, ok := socketUnder(c).(*net.TCPConn); !ok {
		t.Errorf("the client's socket is not reachable through NetConn: %T", socketUnder(c))
	}
}

func socketUnder(c net.Conn) net.Conn {
	for range 10 {
		u, ok := c.(interface{ NetConn() net.Conn })
		if !ok {
			return c
		}
		c = u.NetConn()
	}
	return c
}

// The refusal is in the client's hands when it is closed: gorilla has read
// the 403 and waits for the rest of its body, which a Close ends. The upgrade
// still settles as closed.
func TestAClosedEarlyConnIsClosedNotRefused(t *testing.T) {
	answered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 2048\r\n\r\nforbidden")
		close(answered)
		_, _ = io.Copy(io.Discard, brw)
	}))
	t.Cleanup(srv.Close)

	c, err := DialEarly(context.Background(), DialOpts{URL: strings.Replace(srv.URL, "http", "ws", 1) + "/ws"}, Shape{})
	if err != nil {
		t.Fatal(err)
	}
	<-answered
	// Time for the answer to cross loopback into gorilla's body read.
	time.Sleep(100 * time.Millisecond)
	_ = c.Close()
	<-c.ready
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a read after Close: %v, want net.ErrClosed", err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after Close: %v, want net.ErrClosed", err)
	}
}

func TestARefusedEarlyUpgradeIsAnUpgradeError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)

	c, err := DialEarly(context.Background(), DialOpts{URL: strings.Replace(srv.URL, "http", "ws", 1) + "/ws"}, Shape{})
	if err != nil {
		t.Fatalf("the dial returns before the answer, got %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	var ue *UpgradeError
	if !errors.As(err, &ue) || ue.Status != http.StatusNotFound {
		t.Fatalf("got %v, want an UpgradeError with status 404", err)
	}
	if _, werr := c.Write([]byte("x")); !errors.As(werr, &ue) {
		t.Fatalf("a write after the refusal: %v, want the same UpgradeError", werr)
	}
	if derr := c.SetDeadline(time.Now().Add(time.Second)); !errors.As(derr, &ue) {
		t.Fatalf("a deadline after the refusal: %v, want the same UpgradeError", derr)
	}
}

// silentServer accepts connections and hands their bytes to the test without
// ever answering.
func silentServer(t *testing.T) (addr string, conns <-chan net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ch := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			ch <- c
		}
	}()
	return l.Addr().String(), ch
}

func TestAReadBeforeTheAnswerKeepsItsDeadline(t *testing.T) {
	addr, _ := silentServer(t)
	c, err := DialEarly(context.Background(), DialOpts{URL: "ws://" + addr + "/ws"}, Shape{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(time.Hour))
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("got %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a moved deadline did not end the waiting read")
	}
}

func TestAnEarlyDialStopsWhenItsContextDoes(t *testing.T) {
	// A wss dial to a server that never answers the TLS handshake.
	addr, _ := silentServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := DialEarly(ctx, DialOpts{URL: "wss://" + addr + "/ws"}, Shape{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the context's error", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the dial took %v past its context", d)
	}
}

// The upgrade outlives the dial, but not the deadline of its context: an
// unanswered upgrade closes the socket and surfaces as an UpgradeError.
func TestAnUnansweredEarlyUpgradeEndsWithItsContext(t *testing.T) {
	addr, conns := silentServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	c, err := DialEarly(ctx, DialOpts{URL: "ws://" + addr + "/ws"}, Shape{})
	cancel() // what dialServer does as soon as the dial returns
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	srv := <-conns

	start := time.Now()
	_, err = c.Read(make([]byte, 1))
	var ue *UpgradeError
	if !errors.As(err, &ue) {
		t.Fatalf("got %v, want an UpgradeError", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the upgrade outlived its context by %v", d)
	}
	_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, srv); err != nil {
		t.Fatalf("the client did not close the socket: %v", err)
	}
}

// Early frames are cut by the plan of ShapedConn.Write, before the server
// has said anything: the server here parses them and only then answers.
func TestEarlyFramesGoThroughTheShaper(t *testing.T) {
	const minFrame, maxFrame = 256, 1024
	sizes := []int{60, 129, 700, 1500, 3000, 5000, 8000}
	var want []byte
	for _, n := range sizes {
		want = append(want, payload(n)...)
	}

	addr, conns := silentServer(t)
	c, err := DialEarly(context.Background(), DialOpts{URL: "ws://" + addr + "/ws"}, Shape{MinFrame: minFrame, MaxFrame: maxFrame})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for _, n := range sizes {
		if _, err := c.Write(payload(n)); err != nil {
			t.Fatal(err)
		}
	}

	srv := <-conns
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(srv)
	req, err := http.ReadRequest(br)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	frames := 0
	for len(got) < len(want) {
		p, err := readClientFrame(br)
		if err != nil {
			t.Fatalf("frame %d: %v", frames, err)
		}
		if len(p) > maxFrame {
			t.Errorf("an early frame of %d bytes is above the bound %d", len(p), maxFrame)
		}
		got = append(got, p...)
		frames++
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the early frames do not carry the written bytes")
	}
	// Every write above 128 bytes is at least two frames.
	if least := 1 + 2*(len(sizes)-1); frames < least {
		t.Fatalf("%d writes became %d frames, want at least %d", len(sizes), frames, least)
	}

	// Only now does the server answer, and the connection carries on.
	accept := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, _ = io.WriteString(srv, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+base64.StdEncoding.EncodeToString(accept[:])+"\r\n\r\n")
	_, _ = srv.Write([]byte{0x82, 2, 'o', 'k'})
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "ok" {
		t.Fatalf("after the answer: %q, %v", reply, err)
	}
	if _, err := c.Write(payload(500)); err != nil {
		t.Fatal(err)
	}
	if p, err := readClientFrame(br); err != nil || len(p) > maxFrame || len(p) == 500 {
		t.Fatalf("a write after the answer came as a %d-byte frame (%v), want a shaped piece", len(p), err)
	}
}

// readClientFrame reads one final, masked, binary client frame and unmasks it.
func readClientFrame(r *bufio.Reader) ([]byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 0x82 || h[1]&0x80 == 0 {
		return nil, errors.New("not a final masked binary frame")
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	var key [4]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return nil, err
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, err
	}
	for i := range p {
		p[i] ^= key[i&3]
	}
	return p, nil
}

// earlyWSS is earlyEcho over TLS 1.3, with the certificate pool and pin of
// its self-signed certificate.
func earlyWSS(t *testing.T) (url string, pool *x509.CertPool, pin string) {
	t.Helper()
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(leaf)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)

	up := NewUpgrader(UpgraderOpts{Path: "/ws", EarlyData: true})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		c, err := up.Upgrade(w, r)
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_, _ = io.Copy(c, c)
		}()
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.Replace(srv.URL, "https", "wss", 1) + "/ws", pool, hex.EncodeToString(spki[:])
}

// The early dial does the crypto/tls handshake itself rather than leaving it
// to gorilla. The checks have to survive the move: the pin, the chain.
func TestAnEarlyWSSDialKeepsItsChecks(t *testing.T) {
	url, pool, pin := earlyWSS(t)

	d := NewDialer(DialOpts{URL: url, RootCAs: pool, PinSHA256: []string{pin}})
	c, err := d.DialEarly(context.Background(), Shape{MinFrame: 256, MaxFrame: 1024})
	if err != nil {
		t.Fatal(err)
	}
	msg := payload(2000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo over wss: %v", err)
	}
	if _, ok := socketUnder(c).(*net.TCPConn); !ok {
		t.Errorf("the TLS socket is not reachable through NetConn: %T", socketUnder(c))
	}
	_ = c.Close()

	wrongPin := strings.Repeat("00", 32)
	bad := NewDialer(DialOpts{URL: url, RootCAs: pool, PinSHA256: []string{wrongPin}})
	if _, err := bad.DialEarly(context.Background(), Shape{}); err == nil {
		t.Fatal("an early dial accepted a certificate outside its pin")
	}
	if _, err := DialEarly(context.Background(), DialOpts{URL: url}, Shape{}); err == nil {
		t.Fatal("an early dial accepted a certificate outside the system roots")
	}
}

// Moving the handshake out of gorilla must not move the ClientHello.
func TestAnEarlyDialPutsTheSameClientHelloOnTheWire(t *testing.T) {
	url, pool, _ := earlyWSS(t)
	upstream := strings.TrimSuffix(strings.TrimPrefix(url, "wss://"), "/ws")
	tap := tapHellos(t, upstream)
	tapped := "wss://" + tap.addr + "/ws"

	ordinary, err := NewDialer(DialOpts{URL: tapped, RootCAs: pool}).DialContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = ordinary.Close()
	early, err := NewDialer(DialOpts{URL: tapped, RootCAs: pool}).DialEarly(context.Background(), Shape{})
	if err != nil {
		t.Fatal(err)
	}
	_ = early.Close()

	_, a := tap.hello(t, 0)
	_, b := tap.hello(t, 1)
	if a.JA3String() != b.JA3String() || a.JA4() != b.JA4() {
		t.Fatalf("the early dial changed the ClientHello:\n%s %s\n%s %s", a.JA3String(), a.JA4(), b.JA3String(), b.JA4())
	}
}

// Upgraded turns true with the 101 and not before it. Addresses and
// deadlines belong to the socket on both sides of the answer.
func TestAnEarlyConnBeforeAndAfterTheAnswer(t *testing.T) {
	release := make(chan struct{})
	stand := earlyEcho(t, true, release)
	c, err := NewDialer(DialOpts{URL: stand.url}).DialEarly(context.Background(), Shape{MinFrame: 256, MaxFrame: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Upgraded() {
		t.Fatal("upgraded before the server answered")
	}
	if c.RemoteAddr().String() != stand.addr || c.LocalAddr().String() != socketUnder(c).LocalAddr().String() {
		t.Fatalf("addresses %v -> %v, want the socket's, to %s", c.LocalAddr(), c.RemoteAddr(), stand.addr)
	}
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("a write deadline before the answer: %v", err)
	}

	echo := func(msg []byte) {
		t.Helper()
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatal("the echo differs from what was sent")
		}
	}
	early := payload(600)
	if _, err := c.Write(early); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-stand.upgraded; err != nil {
		t.Fatalf("the upgrader refused early frames: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(early))); err != nil {
		t.Fatal(err)
	}
	if !c.Upgraded() {
		t.Fatal("not upgraded after the echo of the early frames")
	}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("a deadline after the answer: %v", err)
	}
	echo(payload(2000))
}

func TestAnUpgradeErrorNamesItsStatus(t *testing.T) {
	cause := errors.New("bad handshake")
	refused := &UpgradeError{Status: http.StatusForbidden, Err: cause}
	if !strings.Contains(refused.Error(), "status 403") || !errors.Is(refused, cause) {
		t.Fatalf("%q does not name its status or does not wrap its cause", refused.Error())
	}
	silent := &UpgradeError{Err: cause}
	if strings.Contains(silent.Error(), "status") || !errors.Is(silent, cause) {
		t.Fatalf("%q names a status it does not have or does not wrap its cause", silent.Error())
	}
}

func TestDialFramesCarriesFramesAfterTheAnswer(t *testing.T) {
	stand := earlyEcho(t, false, released())
	c, err := NewDialer(DialOpts{URL: stand.url}).DialFrames(context.Background(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	msg := payload(3000)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("the echo differs from what was sent")
	}
}
