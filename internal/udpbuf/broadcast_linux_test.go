package udpbuf

import (
	"golang.org/x/sys/unix"
	"net"
	"testing"
)

func TestRelaySocketCannotSendBroadcast(t *testing.T) {
	c, err := ListenUnicast("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var enabled int
	var getErr error
	if err := raw.Control(func(fd uintptr) { enabled, getErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST) }); err != nil {
		t.Fatal(err)
	}
	if getErr != nil || enabled != 0 {
		t.Fatalf("SO_BROADCAST=%d, error=%v", enabled, getErr)
	}
	if _, err := c.WriteToUDP([]byte("blocked"), &net.UDPAddr{IP: net.IPv4bcast, Port: 9}); err == nil {
		t.Fatal("broadcast write accepted")
	}
}
