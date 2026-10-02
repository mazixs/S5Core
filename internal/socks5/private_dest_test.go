package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestWhichAddressesAreThePrivateOnes(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1":            true,
		"127.1.2.3":            true,
		"::1":                  true,
		"::ffff:127.0.0.1":     true,
		"0.0.0.0":              true,
		"::":                   true,
		"169.254.169.254":      true,
		"fe80::1":              true,
		"10.0.0.1":             true,
		"172.16.5.4":           true,
		"192.168.1.1":          true,
		"fd00::1":              true,
		"::ffff:10.1.1.1":      true,
		"100.64.0.1":           true,
		"100.100.100.200":      true,
		"224.0.0.251":          true,
		"239.255.255.250":      true,
		"ff02::fb":             true,
		"ff05::c":              true,
		"64:ff9b::a00:1":       true,
		"64:ff9b::7f00:1":      true,
		"64:ff9b::808:808":     false,
		"8.8.8.8":              false,
		"100.128.0.1":          false,
		"172.32.0.1":           false,
		"2001:4860:4860::8888": false,
		"::ffff:8.8.8.8":       false,
		"203.0.113.9":          false,
	} {
		if got := privateDestination(netip.MustParseAddr(addr)); got != want {
			t.Errorf("privateDestination(%s) = %v, want %v", addr, got, want)
		}
	}
}

type fixedResolver struct{ ips []net.IP }

func (r fixedResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, r.ips[0], nil
}

func (r fixedResolver) ResolveAll(ctx context.Context, _ string) (context.Context, []net.IP, error) {
	return ctx, r.ips, nil
}

func privateDestServer(t *testing.T, conf *Config) string {
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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() { _ = server.ServeContext(ctx, ln) }()
	return ln.Addr().String()
}

// connectReply asks the server for a CONNECT to a literal address or a name
// and returns the reply code.
func connectReply(t *testing.T, server string, dest *AddrSpec) byte {
	t.Helper()
	var addr []byte
	if dest.FQDN != "" {
		addr = append([]byte{fqdnAddress, byte(len(dest.FQDN))}, dest.FQDN...)
	} else {
		addr = append([]byte{ipv4Address}, dest.IP.To4()...)
	}
	return connectRaw(t, server, addr, dest.Port)
}

// connectRaw sends a CONNECT with the address bytes as given, address type
// first, and returns the reply code.
func connectRaw(t *testing.T, server string, addr []byte, port int) byte {
	t.Helper()
	conn, err := net.Dial("tcp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, ConnectCommand, 0}, addr...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("no reply: %v", err)
	}
	return reply[1]
}

// A client of the proxy may not reach the machine the proxy runs on or the
// network behind it, whether it names an address or a name that resolves to
// one (docs/plan/draft.md, Ч-27). The listener below stands for such a
// service: it must not be connected to.
func TestAConnectToThePrivateNetworkIsRefused(t *testing.T) {
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	connected := make(chan struct{}, 4)
	go func() {
		for {
			c, err := service.Accept()
			if err != nil {
				return
			}
			connected <- struct{}{}
			_ = c.Close()
		}
	}()
	port := service.Addr().(*net.TCPAddr).Port

	loopback := []net.IP{net.ParseIP("127.0.0.1")}
	for _, tc := range []struct {
		name     string
		deny     bool
		dest     *AddrSpec
		resolver NameResolver
		want     byte
	}{
		{"a literal", true, &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: port}, nil, ruleFailure},
		{"a name for one address", true, &AddrSpec{FQDN: "internal.example", Port: port}, fixedResolver{loopback}, ruleFailure},
		{"a name for several addresses", true, &AddrSpec{FQDN: "internal.example", Port: port},
			fixedResolver{[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}, ruleFailure},
		{"the same literal when it is allowed", false, &AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: port}, nil, successReply},
		{"the same name when it is allowed", false, &AddrSpec{FQDN: "internal.example", Port: port}, fixedResolver{loopback}, successReply},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &Config{DenyPrivateDest: tc.deny}
			if tc.resolver != nil {
				conf.Resolver = tc.resolver
			}
			if got := connectReply(t, privateDestServer(t, conf), tc.dest); got != tc.want {
				t.Fatalf("reply 0x%02x, want 0x%02x", got, tc.want)
			}
			wait := 200 * time.Millisecond
			if !tc.deny {
				wait = 5 * time.Second
			}
			select {
			case <-connected:
				if tc.deny {
					t.Fatal("the server connected to a private address it was told to refuse")
				}
			case <-time.After(wait):
				if !tc.deny {
					t.Fatal("the server did not connect to an address it was allowed to")
				}
			}
		})
	}
}

// A name that resolves to a private address and a public one is dialled at the
// public one only.
func TestANameWithAPublicAddressIsDialledAtThatOne(t *testing.T) {
	var mu sync.Mutex
	var dialled []string
	conf := &Config{
		DenyPrivateDest: true,
		Resolver:        fixedResolver{[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("203.0.113.9"), net.ParseIP("10.0.0.5")}},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			mu.Lock()
			dialled = append(dialled, addr)
			mu.Unlock()
			return nil, errors.New("not reachable in a test")
		},
	}
	connectReply(t, privateDestServer(t, conf), &AddrSpec{FQDN: "mixed.example", Port: 443})

	mu.Lock()
	defer mu.Unlock()
	if len(dialled) == 0 {
		t.Fatal("nothing was dialled")
	}
	for _, addr := range dialled {
		if addr != "203.0.113.9:443" {
			t.Errorf("dialled %s, want only 203.0.113.9:443", addr)
		}
	}
}

// Every datagram of the three UDP commands is checked where it leaves, so a
// name that resolves to the server's own address is dropped like the address
// itself. Each case has its control: the same datagram reaches the sink when
// the server allows it.
func TestADatagramToThePrivateNetworkIsDropped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command byte
		dest    func(sink *udpSink) *AddrSpec
	}{
		{"associate, by address", AssociateCommand, func(s *udpSink) *AddrSpec { return s.spec() }},
		{"tunnel, by address", UDPTunnelCommand, func(s *udpSink) *AddrSpec { return s.spec() }},
		{"tunnel, by name", UDPTunnelCommand, func(s *udpSink) *AddrSpec {
			return &AddrSpec{FQDN: "internal.example", Port: s.spec().Port}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, deny := range []bool{false, true} {
				sink := newUDPSink(t, false)
				dest := tc.dest(sink)
				addr := privateDestServer(t, &Config{
					DenyPrivateDest: deny,
					Resolver:        fixedResolver{[]net.IP{net.ParseIP("127.0.0.1")}},
				})
				setup := []byte{0x01, 127, 0, 0, 1, byte(dest.Port >> 8), byte(dest.Port)}
				conn, reply := associateThrough(t, addr, tc.command, setup)
				datagram := BuildUDPHeader(dest, []byte("question"))

				if tc.command == AssociateCommand {
					proxy := &net.UDPAddr{IP: net.IPv4(reply[4], reply[5], reply[6], reply[7]), Port: int(reply[8])<<8 | int(reply[9])}
					client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = client.Close() }()
					if _, err := client.WriteToUDP(datagram, proxy); err != nil {
						t.Fatal(err)
					}
				} else {
					frame := binary.BigEndian.AppendUint16(nil, uint16(len(datagram)))
					if _, err := conn.Write(append(frame, datagram...)); err != nil {
						t.Fatal(err)
					}
				}

				silent := sink.receivedNothing(t, 400*time.Millisecond)
				if deny && !silent {
					t.Fatal("a datagram reached a private address the server was told to refuse")
				}
				if !deny && silent {
					t.Fatal("control: the datagram did not reach the sink on a server that allows it")
				}
			}
		})
	}
}

// Addresses a client can write in a form that is not a plain IPv4 literal are
// refused as what they point to, and a request that names nothing is refused
// rather than dialled at the machine's own host, which is what an empty host
// means to the dialer. Each is checked against a listener that must stay
// unconnected, on a server that does not deny, as the control that the request
// would otherwise have gone through.
func TestARequestThatHidesAPrivateAddressIsRefused(t *testing.T) {
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	port := service.Addr().(*net.TCPAddr).Port
	connected := make(chan struct{}, 4)
	go func() {
		for {
			c, err := service.Accept()
			if err != nil {
				return
			}
			connected <- struct{}{}
			_ = c.Close()
		}
	}()

	mapped := append([]byte{ipv6Address}, net.ParseIP("::ffff:127.0.0.1").To16()...)
	nat64 := append([]byte{ipv6Address}, net.ParseIP("64:ff9b::7f00:1").To16()...)
	empty := []byte{fqdnAddress, 0}
	for name, addr := range map[string][]byte{"IPv4-mapped": mapped, "NAT64": nat64, "an empty name": empty} {
		t.Run(name, func(t *testing.T) {
			if got := connectRaw(t, privateDestServer(t, &Config{DenyPrivateDest: true}), addr, port); got != ruleFailure {
				t.Fatalf("reply 0x%02x, want 0x%02x", got, ruleFailure)
			}
			select {
			case <-connected:
				t.Fatal("the server connected to the private address behind the request")
			case <-time.After(200 * time.Millisecond):
			}
		})
	}

	t.Run("IPv4-mapped, control", func(t *testing.T) {
		if got := connectRaw(t, privateDestServer(t, &Config{}), mapped, port); got != successReply {
			t.Fatalf("reply 0x%02x, want 0x%02x on a server that allows it", got, successReply)
		}
		select {
		case <-connected:
		case <-time.After(5 * time.Second):
			t.Fatal("control: the request did not reach the listener on a server that allows it")
		}
	})
}

// The native command is the third way a datagram leaves, and its client sends
// them over a path of its own, so it has its own case: the same datagram is
// dropped under the ban and reaches the sink without it.
func TestANativeDatagramToThePrivateNetworkIsDropped(t *testing.T) {
	for _, deny := range []bool{false, true} {
		sink := newUDPSink(t, false)
		native := newScriptedNative()
		reply, conn, _ := nativeRequest(t, &Config{
			DenyPrivateDest: deny,
			NativeUDP:       func(net.Conn) (NativeAssociation, error) { return native, nil },
		})
		if reply[1] != successReply {
			t.Fatalf("reply %x, want success", reply)
		}
		defer func() { _ = conn.Close() }()
		native.in <- scriptedDatagram{data: BuildUDPHeader(sink.spec(), []byte("question"))}

		silent := sink.receivedNothing(t, 400*time.Millisecond)
		if deny && !silent {
			t.Fatal("a native datagram reached a private address the server was told to refuse")
		}
		if !deny && silent {
			t.Fatal("control: the native datagram did not reach the sink on a server that allows it")
		}
	}
}

// The address a connection to the server's own public address leaves by is the
// loopback, so the address is the server's own as much as 127.0.0.1 is.
func TestTheServersOwnAddressIsRefusedInEveryForm(t *testing.T) {
	server, err := New(&Config{DenyPrivateDest: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	server.own.read = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9")}
	}
	for addr, want := range map[string]bool{
		"203.0.113.9":        true,
		"::ffff:203.0.113.9": true,
		"2001:db8::9":        true,
		"203.0.113.10":       false,
		"2001:db8::10":       false,
	} {
		if got := server.deniedDestination(netip.MustParseAddr(addr)); got != want {
			t.Errorf("deniedDestination(%s) = %v, want %v", addr, got, want)
		}
	}
	server.config.DenyPrivateDest = false
	if server.deniedDestination(netip.MustParseAddr("203.0.113.9")) {
		t.Error("the server's own address is refused although the server allows private destinations")
	}
}

// The list of the server's addresses is read once and again only after it has
// aged, not for every datagram.
func TestTheServersAddressesAreReadOncePerMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var reads int
		own := &ownAddresses{read: func() []netip.Addr {
			reads++
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}
		}}
		for range 1000 {
			own.has(netip.MustParseAddr("198.51.100.1"))
		}
		if reads != 1 {
			t.Fatalf("%d reads for 1000 lookups within a minute", reads)
		}
		time.Sleep(ownAddressesTTL + time.Second)
		own.has(netip.MustParseAddr("198.51.100.1"))
		if reads != 2 {
			t.Fatalf("%d reads after the list aged, want 2", reads)
		}
	})
}
