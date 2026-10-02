package s5server

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Port 0 used to start the native hub on an ephemeral port: the clients were
// told a port that no firewall rule or container mapping opens, and that
// changes on every restart (finding 7 of the 2.3 review).
func TestUDPPortZeroIsAConfigurationError(t *testing.T) {
	base := DefaultConfig()
	base.RequireAuth = false
	base.ObfsEnabled, base.ObfsPort, base.ObfsPSK = true, "1443", testPSK

	for _, port := range []string{"0", "00", "-1", "65536", "udp"} {
		cfg := base
		cfg.UDPPort = port
		err := ValidateConfig(cfg)
		if err == nil {
			t.Errorf("UDP_PORT %q was accepted", port)
			continue
		}
		if !strings.Contains(err.Error(), "from 1 to 65535") || !strings.Contains(err.Error(), "leave it empty") {
			t.Errorf("UDP_PORT %q: the error does not name the range or the way to disable it: %v", port, err)
		}
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("NewServer accepted UDP_PORT %q", port)
		}
	}

	for _, port := range []string{"1", "65535"} {
		cfg := base
		cfg.UDPPort = port
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("UDP_PORT %q was rejected: %v", port, err)
		}
	}
}

// Empty is not a port, it is "no native UDP": it needs no tunnel listener
// and starts no hub.
func TestAnEmptyUDPPortDisablesNativeUDP(t *testing.T) {
	cfg := Config{
		Port: reservePort(t), ListenIP: "127.0.0.1", RequireAuth: false,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("an empty UDP_PORT was rejected: %v", err)
	}
	if srv := startServer(t, cfg); srv.nativeHub.Load() != nil {
		t.Fatal("an empty UDP_PORT started the native hub")
	}
}

// reserveUDPPort is reservePort for UDP: 0 is refused, so native tests take a
// free port and read the bound one back from the hub.
func reserveUDPPort(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(port)
}
