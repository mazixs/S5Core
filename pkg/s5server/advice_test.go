package s5server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/obfs"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Plan task Ф5-7: "the transport profile of a client in the field changes
// without replacing the binary, and telemetry shows the distribution of
// versions and transports". The server's half of that is here: what it
// tells clients, how that is changed while it runs, and what it counts.

func TestParseTransportAdvice(t *testing.T) {
	tests := []struct {
		raw  string
		want *obfs.Advice
	}{
		{"", nil},
		{"   ", nil},
		{"ws", &obfs.Advice{Transport: "ws"}},
		{"transport=obfs", &obfs.Advice{Transport: "obfs"}},
		{"ws min_frame=512 max_frame=2048", &obfs.Advice{Transport: "ws", WSMinFrame: 512, WSMaxFrame: 2048}},
		{"ws,min_frame=512,max_frame=2048,jitter_ms=5", &obfs.Advice{Transport: "ws", WSMinFrame: 512, WSMaxFrame: 2048, WSMaxJitterMs: 5}},
		{"padding=128", &obfs.Advice{MaxPadding: 128}},
		{"keepalive=10s-20s", &obfs.Advice{KeepaliveMin: 10 * time.Second, KeepaliveMax: 20 * time.Second}},
		{"transport=ws min_frame=1 max_frame=65535 jitter_ms=60000 padding=4096 keepalive=1s-3600s",
			&obfs.Advice{Transport: "ws", WSMinFrame: 1, WSMaxFrame: 65535, WSMaxJitterMs: 60000, MaxPadding: 4096, KeepaliveMin: time.Second, KeepaliveMax: time.Hour}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.raw), func(t *testing.T) {
			got, err := ParseTransportAdvice(tt.raw)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			switch {
			case got == nil && tt.want == nil:
			case got == nil || tt.want == nil || *got != *tt.want:
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	// Every refusal names what is wrong, because the operator sees only
	// the message and the variable they typed.
	refused := []struct {
		raw, wantInError string
	}{
		{"plain", "transport"},
		{"http", "transport"},
		{"ws obfs", "twice"},
		{"min_frame=abc max_frame=10", "not a number"},
		{"min_frame=0 max_frame=10", "outside"},
		{"min_frame=2048 max_frame=512", "exceeds"},
		{"min_frame=512", "together"},
		{"max_frame=512", "together"},
		{"padding=5000", "outside"},
		{"jitter_ms=-1", "outside"},
		{"keepalive=10s", "range"},
		{"keepalive=20s-10s", "below"},
		{"keepalive=500ms-20s", "outside"},
		{"keepalive=10s-20500ms", "whole seconds"},
		{"keepalive=1s-2h", "outside"},
		{"colour=blue", "unknown field"},
		{"transport=", "transport"},
	}
	for _, tt := range refused {
		t.Run(fmt.Sprintf("refuses %q", tt.raw), func(t *testing.T) {
			got, err := ParseTransportAdvice(tt.raw)
			if err == nil {
				t.Fatalf("accepted as %+v", got)
			}
			if !strings.Contains(err.Error(), tt.wantInError) {
				t.Fatalf("error %q does not mention %q", err, tt.wantInError)
			}
		})
	}
}

func TestATransportAdviceMustNameARunningTransport(t *testing.T) {
	base := DefaultConfig()
	base.RequireAuth = false
	base.ObfsEnabled = true
	base.ObfsPSK = testPSK
	base.WSEnabled = false

	cfg := base
	cfg.TransportAdvice = "ws"
	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("an advice pointing at the disabled WS listener was accepted")
	}
	if !strings.Contains(err.Error(), "TRANSPORT_ADVICE") || !strings.Contains(err.Error(), "WS_ENABLED") {
		t.Fatalf("the error names neither the variable nor the cause: %v", err)
	}
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("NewServer accepted what ValidateConfig refuses")
	}

	cfg = base
	cfg.TransportAdvice = "quic"
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "TRANSPORT_ADVICE") {
		t.Fatalf("an unparsable advice was accepted or the error does not name the variable: %v", err)
	}

	cfg = base
	cfg.TransportAdvice = "obfs padding=64"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("an advice naming the running obfs listener was refused: %v", err)
	}

	cfg = base
	cfg.ObfsEnabled = false
	cfg.TransportAdvice = "obfs"
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "OBFS_ENABLED") {
		t.Fatalf("an advice pointing at the disabled obfs listener was accepted or the error does not say so: %v", err)
	}
}

// The advice rides in a control frame, and a control frame that does not fit
// the MTU is refused when the connection is set up - after the listener has
// already accepted it. A server whose TRANSPORT_ADVICE did not fit its
// OBFS_MTU would therefore start, listen, and refuse every obfuscated
// connection it accepted, naming the cause nowhere the operator is looking
// (review finding R03).
//
// There is no size check in ParseTransportAdvice because the configuration
// that would need one cannot be written. What the parser accepts encodes to
// at most 30 bytes - a transport name of four, plus six numeric fields of
// four - and the smallest MTU ValidateConfig accepts leaves 41. This test is
// that arithmetic run rather than asserted: the largest advice the parser
// will produce, over a server at obfs.MinMTU, under the largest hello a
// client can send, carrying real traffic. Add a field to Advice or to Hello,
// lengthen a transport name, raise the string bound or the frame overhead,
// and the refusal lands here instead of in the field.
func TestTheLargestAdviceStillFitsTheSmallestFrame(t *testing.T) {
	// Every field at the top of the range the parser allows. The numbers do
	// not change the size - a uint16 field is four bytes whatever it holds -
	// but the set of fields does, and this is all of them.
	const largest = "transport=obfs min_frame=1 max_frame=65535 jitter_ms=60000 padding=4096 keepalive=3600s-3600s"
	want := obfs.Advice{
		Transport:     "obfs",
		WSMinFrame:    1,
		WSMaxFrame:    65535,
		WSMaxJitterMs: 60000,
		MaxPadding:    4096,
		KeepaliveMin:  3600 * time.Second,
		KeepaliveMax:  3600 * time.Second,
	}
	parsed, err := ParseTransportAdvice(largest)
	if err != nil {
		t.Fatalf("the parser refused the advice this test is about: %v", err)
	}
	if *parsed != want {
		t.Fatalf("parsed %+v, want %+v", *parsed, want)
	}

	echo := startEchoServer(t)
	cfg := Config{
		ListenIP:        "127.0.0.1",
		Port:            reservePort(t),
		ObfsEnabled:     true,
		ObfsPort:        reservePort(t),
		ObfsPSK:         testPSK,
		ObfsMaxPadding:  64,
		ObfsMTU:         obfs.MinMTU,
		RequireAuth:     false,
		TransportAdvice: largest,
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("the smallest MTU with the largest advice was refused by the configuration: %v", err)
	}
	startServer(t, cfg)

	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+cfg.ObfsPort, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	got := make(chan obfs.Advice, 1)
	tunnel, err := obfs.NewClientConn(raw, obfs.Config{
		PSK:        []byte(testPSK),
		MTU:        obfs.MinMTU,
		MaxPadding: 64,
		// The largest hello a client of this tree can send: a version longer
		// than the format carries, which the encoder cuts, and the longer of
		// the two transport names.
		Hello:    &obfs.Hello{Version: strings.Repeat("v", 200), Transport: "obfs"},
		OnAdvice: func(a obfs.Advice) { got <- a },
	})
	if err != nil {
		t.Fatalf("a client at the smallest MTU could not send its hello: %v", err)
	}
	_ = tunnel.SetDeadline(time.Now().Add(10 * time.Second))
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("the tunnel at the smallest MTU did not carry a CONNECT: %v\n"+
			"a control frame larger than the MTU is refused when the connection is set up, "+
			"so check the size of Advice and Hello against obfs.MinMTU minus the frame overhead", err)
	}

	// Traffic, not just a handshake: at this MTU a payload of any size is
	// several frames, and the advice frame went out ahead of the first of
	// them.
	payload := bytes.Repeat([]byte("advice at the smallest frame. "), 8)
	if _, err := tunnel.Write(payload); err != nil {
		t.Fatalf("writing through the tunnel: %v", err)
	}
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, back); err != nil {
		t.Fatalf("reading the echo back: %v", err)
	}
	if !bytes.Equal(back, payload) {
		t.Fatalf("the echo came back changed at MTU %d", obfs.MinMTU)
	}

	select {
	case a := <-got:
		if a != want {
			t.Fatalf("the client got %+v, want %+v", a, want)
		}
	default:
		t.Fatalf("no advice reached a client at MTU %d, though the connection worked", obfs.MinMTU)
	}
}

// adviceStand starts a server on the obfuscated listener alone, with the
// given advice, and returns it with its port and an echo target.
func adviceStand(t *testing.T, advice string, telemetry *Telemetry) (*Server, string, string) {
	t.Helper()
	echo := startEchoServer(t)
	cfg := Config{
		ListenIP:        "127.0.0.1",
		Port:            reservePort(t),
		ObfsEnabled:     true,
		ObfsPort:        reservePort(t),
		ObfsPSK:         testPSK,
		ObfsMaxPadding:  64,
		ObfsMTU:         1400,
		RequireAuth:     false,
		TransportAdvice: advice,
		Telemetry:       telemetry,
	}
	srv := startServer(t, cfg)
	return srv, cfg.ObfsPort, echo
}

// dialAdvised opens a tunnel to the obfuscated port with the given control
// settings and runs the SOCKS5 CONNECT through it, which is the exchange
// that carries the hello up and the advice down.
func dialAdvised(t *testing.T, port, echo string, cfg obfs.Config) net.Conn {
	t.Helper()
	raw, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	cfg.PSK = []byte(testPSK)
	cfg.MaxPadding = 64
	cfg.MTU = 1400
	tunnel, err := obfs.NewClientConn(raw, cfg)
	if err != nil {
		t.Fatalf("obfs wrap: %v", err)
	}
	_ = tunnel.SetDeadline(time.Now().Add(5 * time.Second))
	if err := connectAsMember(tunnel, echo); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return tunnel
}

func TestTheServerAdvisesEveryClientAndChangesItsMindWithoutARestart(t *testing.T) {
	srv, port, echo := adviceStand(t, "transport=obfs padding=32 keepalive=10s-20s", nil)

	got := make(chan obfs.Advice, 1)
	onAdvice := func(a obfs.Advice) { got <- a }

	// The advice arrives with the first thing the server says, so by the
	// time CONNECT has been answered it is already in hand.
	dialAdvised(t, port, echo, obfs.Config{OnAdvice: onAdvice})
	want := obfs.Advice{Transport: "obfs", MaxPadding: 32, KeepaliveMin: 10 * time.Second, KeepaliveMax: 20 * time.Second}
	select {
	case a := <-got:
		if a != want {
			t.Fatalf("client got %+v, want %+v", a, want)
		}
	default:
		t.Fatal("no advice arrived with the SOCKS5 reply")
	}

	// Changed on the fly: the next connection gets the new advice. This is
	// what SIGHUP does with a changed TRANSPORT_ADVICE.
	if err := srv.UpdateTransportAdvice("obfs padding=48"); err != nil {
		t.Fatalf("UpdateTransportAdvice: %v", err)
	}
	dialAdvised(t, port, echo, obfs.Config{OnAdvice: onAdvice})
	select {
	case a := <-got:
		if a != (obfs.Advice{Transport: "obfs", MaxPadding: 48}) {
			t.Fatalf("client got %+v after the update", a)
		}
	default:
		t.Fatal("no advice arrived after the update")
	}

	// An update that would send clients to a listener this server does not
	// run is refused, and the previous advice stays in force.
	if err := srv.UpdateTransportAdvice("ws"); err == nil {
		t.Fatal("an advice pointing at the disabled WS listener was applied at runtime")
	}
	dialAdvised(t, port, echo, obfs.Config{OnAdvice: onAdvice})
	select {
	case a := <-got:
		if a.MaxPadding != 48 {
			t.Fatalf("the refused update changed the advice to %+v", a)
		}
	default:
		t.Fatal("no advice arrived after the refused update")
	}

	// Cleared: nothing is sent, and the client's callback stays silent.
	if err := srv.UpdateTransportAdvice(""); err != nil {
		t.Fatalf("clearing the advice: %v", err)
	}
	dialAdvised(t, port, echo, obfs.Config{OnAdvice: onAdvice})
	select {
	case a := <-got:
		t.Fatalf("an advice %+v arrived after the advice was cleared", a)
	default:
	}
}

// collectClientConnections reads s5core_client_connections_total and checks
// its label set on the way: exactly client_version and transport, nothing
// that could name a peer (docs/design/observability-policy.md).
func collectClientConnections(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	counts := map[string]int64{}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_client_connections_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				if dp.Attributes.Len() != 2 {
					t.Errorf("%s: expected exactly 2 labels, got %d: %v", m.Name, dp.Attributes.Len(), dp.Attributes.ToSlice())
				}
				version, ok := dp.Attributes.Value("client_version")
				if !ok {
					t.Errorf("%s: no client_version label", m.Name)
				}
				transport, ok := dp.Attributes.Value("transport")
				if !ok {
					t.Errorf("%s: no transport label", m.Name)
				}
				if strings.ContainsAny(version.Emit(), ":/ @") {
					t.Errorf("%s: client_version %q looks like something other than a build", m.Name, version.Emit())
				}
				counts[version.Emit()+"/"+transport.Emit()] += dp.Value
			}
		}
	}
	return counts
}

func TestClientBuildsAreCountedByTransport(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}
	_, port, echo := adviceStand(t, "", telemetry)

	// Two on the current build, one on a release candidate, one that says
	// nothing about itself (an older client), and one whose "version" is
	// not a version at all.
	dialAdvised(t, port, echo, obfs.Config{Hello: &obfs.Hello{Version: "v1.4.0", Transport: "obfs"}})
	dialAdvised(t, port, echo, obfs.Config{Hello: &obfs.Hello{Version: "v1.4.0", Transport: "obfs"}})
	dialAdvised(t, port, echo, obfs.Config{Hello: &obfs.Hello{Version: "v1.5.0-rc1", Transport: "ws"}})
	dialAdvised(t, port, echo, obfs.Config{})
	dialAdvised(t, port, echo, obfs.Config{Hello: &obfs.Hello{Version: "10.0.0.1:443 alice@example"}})

	counts := collectClientConnections(t, reader)
	want := map[string]int64{
		"v1.4.0/obfs": 2,
		// The transport label is the listener's, not what the client
		// believed: this one claimed ws and arrived on obfs.
		"v1.5.0-rc1/obfs": 1,
		// Cut down to what a build identifier is made of.
		"10.0.0.1443aliceexample/obfs": 1,
	}
	if len(counts) != len(want) {
		t.Fatalf("counted %v, want %v", counts, want)
	}
	for k, v := range want {
		if counts[k] != v {
			t.Errorf("%s: got %d, want %d (all: %v)", k, counts[k], v, counts)
		}
	}
}

func TestTheVersionLabelIsFenced(t *testing.T) {
	t.Run("sanitize", func(t *testing.T) {
		tests := map[string]string{
			"":                                       "unknown",
			"v1.2.3":                                 "v1.2.3",
			"abc123-dirty":                           "abc123-dirty",
			"v1.2.3+build.7":                         "v1.2.3+build.7",
			"v1 2\n3":                                "v123",
			"<script>alert(1)</script>":              "scriptalert1script",
			"\x00\xff":                               "unknown",
			strings.Repeat("v", maxVersionLength+20): strings.Repeat("v", maxVersionLength),
			"версия":                                 "unknown",
		}
		for in, want := range tests {
			if got := sanitizeVersion(in); got != want {
				t.Errorf("sanitizeVersion(%q) = %q, want %q", in, got, want)
			}
		}
	})

	t.Run("a bounded number of builds are named", func(t *testing.T) {
		var v versionLabels
		for i := range maxVersionLabels {
			name := fmt.Sprintf("v1.%d.0", i)
			if got := v.label(name); got != name {
				t.Fatalf("build %d of %d was labelled %q", i+1, maxVersionLabels, got)
			}
		}
		if got := v.label("v9.9.9"); got != versionOther {
			t.Fatalf("build %d was labelled %q, want %q", maxVersionLabels+1, got, versionOther)
		}
		// Known builds keep their names after the set is full, and the two
		// reserved values never took a slot.
		if got := v.label("v1.3.0"); got != "v1.3.0" {
			t.Fatalf("a known build was relabelled %q once the set was full", got)
		}
		if got := v.label(""); got != versionUnknown {
			t.Fatalf("an empty version was labelled %q", got)
		}
		if got := v.label("other"); got != versionOther {
			t.Fatalf("a client calling itself %q was labelled %q", versionOther, got)
		}
	})
}
