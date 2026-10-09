package s5server

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/userstore"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestCONNECTCountsPayloadOnceAndBillsBothDirections(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	data, err := json.Marshal(userstore.UsersFile{Users: []userstore.UserAccount{{ID: "a", Username: "alice", Password: "p", Enabled: true, TrafficLimitBytes: 400}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	cfg := Config{ListenIP: "127.0.0.1", Port: reservePort(t), Telemetry: tel, RequireAuth: true, UsersFile: path}
	s := startServer(t, cfg)
	c, err := net.Dial("tcp", "127.0.0.1:"+cfg.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var answer [2]byte
	if _, err = io.ReadFull(c, answer[:]); err != nil || answer != [2]byte{5, 2} {
		t.Fatal("method", answer, err)
	}
	if _, err = c.Write([]byte{1, 5, 'a', 'l', 'i', 'c', 'e', 1, 'p'}); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(c, answer[:]); err != nil || answer != [2]byte{1, 0} {
		t.Fatal("auth", answer, err)
	}
	port := target.Addr().(*net.TCPAddr).Port
	if _, err = c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err = io.ReadFull(c, reply); err != nil || reply[1] != 0 {
		t.Fatal("CONNECT", reply, err)
	}
	payload := bytes.Repeat([]byte{7}, 200)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 200)
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("payload", err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_, _ = io.Copy(io.Discard, c)
	until := time.Now().Add(3 * time.Second)
	for s.connsEnded.Load() == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if counterValue(t, reader, "s5core_traffic_bytes_in") != 200 || counterValue(t, reader, "s5core_traffic_bytes_out") != 200 {
		t.Fatal("CONNECT metrics include framing or repeat payload")
	}
	acc, ok := s.userStore.Lookup("alice")
	if !ok || acc.TrafficUsedBytes != 400 || s.userStore.SessionStatus("alice") != userstore.SessionQuotaExceeded {
		t.Fatalf("quota usage %d, status %v", acc.TrafficUsedBytes, s.userStore.SessionStatus("alice"))
	}
}

func TestUDPFallbackCountsPayloadOnceAndSeparatesTCPFraming(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		var b [2048]byte
		n, peer, err := echo.ReadFromUDP(b[:])
		if err == nil {
			_, _ = echo.WriteToUDP(b[:n], peer)
		}
	}()
	cfg := Config{ListenIP: "127.0.0.1", Port: reservePort(t), Telemetry: tel}
	srv := startServer(t, cfg)
	c, err := net.Dial("tcp", "127.0.0.1:"+cfg.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if code := socksOver(t, c, socks5.UDPTunnelCommand, []byte{1, 0, 0, 0, 0, 0, 0}); code != 0 {
		t.Fatalf("reply %d", code)
	}
	streamBefore := counterValue(t, reader, "s5core_tcp_stream_bytes_in")
	want := bytes.Repeat([]byte{0x41}, 100)
	to := echo.LocalAddr().(*net.UDPAddr)
	packet := socks5.AppendUDPHeader(nil, &socks5.AddrSpec{IP: to.IP, Port: to.Port})
	packet = append(packet, want...)
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	frame = append(frame, packet...)
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(c, p); err != nil {
		t.Fatal(err)
	}
	headerLen, _, err := socks5.ParseUDPHeader(p)
	if err != nil || !bytes.Equal(p[headerLen:], want) {
		t.Fatalf("reply length %d, error %v", len(p)-headerLen, err)
	}
	_ = c.Close()
	for until := time.Now().Add(5 * time.Second); srv.connsEnded.Load() == 0 && time.Now().Before(until); {
		time.Sleep(time.Millisecond)
	}
	if srv.connsEnded.Load() == 0 {
		t.Fatal("association did not release")
	}
	if in := counterValue(t, reader, "s5core_traffic_bytes_in"); in != 100 {
		t.Fatalf("payload in=%d, want 100", in)
	}
	if out := counterValue(t, reader, "s5core_traffic_bytes_out"); out != 100 {
		t.Fatalf("payload out=%d, want 100", out)
	}
	if delta := counterValue(t, reader, "s5core_tcp_stream_bytes_in") - streamBefore; delta != int64(len(frame)) {
		t.Fatalf("stream delta=%d, frame=%d", delta, len(frame))
	}
}
