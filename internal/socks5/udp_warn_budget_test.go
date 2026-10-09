package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type udpWarnBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *udpWarnBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *udpWarnBuffer) contents() string { b.Lock(); defer b.Unlock(); return b.String() }

func TestMalformedUDPTunnelWarningsAreBoundedAndValidTrafficSurvives(t *testing.T) {
	var log udpWarnBuffer
	var drops atomic.Uint64
	_, stream, served := nativeRequest(t, &Config{
		Logger:    slog.New(slog.NewTextHandler(&log, nil)),
		NativeUDP: func(net.Conn) (NativeAssociation, error) { return nil, nil },
		OnUDPDrop: func(reason string) {
			if reason == UDPDropInvalidHeader {
				drops.Add(1)
			}
		},
	})
	for range 300 {
		if _, err := stream.Write([]byte{0, 1, 0}); err != nil {
			t.Fatal(err)
		}
	}
	target, _ := udpEchoServer(t)
	want := []byte("valid after malformed burst")
	packet := BuildUDPHeader(&AddrSpec{IP: target.IP, Port: target.Port}, want)
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	if _, err := stream.Write(append(frame, packet...)); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatal(err)
	}
	header, _, err := ParseUDPHeader(reply)
	if err != nil || !bytes.Equal(reply[header:], want) {
		t.Fatal("valid datagram did not survive")
	}
	_ = stream.Close()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("association did not release")
	}
	if got := drops.Load(); got != 300 {
		t.Fatalf("drops=%d, want 300", got)
	}
	if got := strings.Count(log.contents(), "level=WARN"); got != 1 {
		t.Fatalf("warnings=%d, want 1", got)
	}
}
