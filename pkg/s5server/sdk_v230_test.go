package s5server_test

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/pkg/nativeudp"
	"github.com/mazixs/S5Core/pkg/obfs"
	"github.com/mazixs/S5Core/pkg/s5server"
	"github.com/mazixs/S5Core/pkg/transport/tlsdecoy"
	"github.com/mazixs/S5Core/pkg/transport/ws"
	"github.com/mazixs/S5Core/pkg/veil"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// The conversions compile only if the v2.3.0 fields, types and order still
// match. They check positional literals without suppressing go vet.
var (
	_ = nativeudp.Probe(struct {
		Heard       bool
		Limit, Size int
	}{false, 0, 0})
	_ = nativeudp.Stats(struct {
		Accepted, TagDrops, ReplayDrops, AuthDrops, ReadErrors uint64
		Active                                                 int
	}{0, 0, 0, 0, 0, 0})
	_ = obfs.Advice(struct {
		Transport                                         string
		WSMinFrame, WSMaxFrame, WSMaxJitterMs, MaxPadding int
		KeepaliveMin, KeepaliveMax                        time.Duration
	}{"ws", 256, 4096, 0, 64, 0, 0})
	_ = s5server.Config(struct {
		Port, ListenIP                                                                         string
		RequireAuth                                                                            bool
		AllowedDestFqdn                                                                        string
		DenyPrivateDest                                                                        bool
		AllowedIPs                                                                             []string
		ReadTimeout, WriteTimeout, HandshakeTimeout, DialTimeout, FrameTimeout, QuotaGrace     time.Duration
		Dial                                                                                   func(context.Context, string, string) (net.Conn, error)
		MaxConnections, Fail2BanRetries                                                        int
		Fail2BanTime                                                                           time.Duration
		Logger                                                                                 *slog.Logger
		Telemetry                                                                              *s5server.Telemetry
		ObfsEnabled                                                                            bool
		ObfsPort, UDPPort, ObfsPSK                                                             string
		ObfsMaxPadding, ObfsMTU, ObfsReplayWindow                                              int
		ObfsNodeID                                                                             string
		ObfsAcceptNodeIDs                                                                      []string
		ObfsRequireMemberKey                                                                   bool
		ObfsKeepaliveMin, ObfsKeepaliveMax                                                     time.Duration
		WSEnabled                                                                              bool
		WSAddr, WSCertFile, WSKeyFile, WSPath, WSSubprotocol, WSDecoyUpstream, TransportAdvice string
		WSMinFrame, WSMaxFrame                                                                 int
		WSMaxJitter                                                                            time.Duration
		UDPTunnelTCPTuningOff                                                                  bool
		UsersFile                                                                              string
		TrafficFlushInterval                                                                   time.Duration
		KDFMemoryBudget                                                                        int64
		SessionLog, SessionLogFile                                                             string
		SessionLogMaxSize                                                                      int64
		SessionLogMaxFiles                                                                     int
		SessionLogMaxAge                                                                       time.Duration
		SessionLogDst                                                                          string
	}{})
	_ = tlsdecoy.Config(struct {
		Addr, CertFile, KeyFile, WSPath, DecoyHTML, DecoyUpstream string
		Subprotocols                                              []string
		MaxFrame                                                  int
		Logger                                                    *slog.Logger
	}{"", "", "", "/ws", "", "", nil, 0, nil})
	_ = ws.UpgraderOpts(struct {
		Path            string
		Subprotocols    []string
		CheckOrigin     func(*http.Request) bool
		ReadLimit       int64
		WriteBufferSize int
	}{"/ws", nil, nil, 0, 0})

	_ func([]byte) (nativeudp.Probe, bool)                                           = nativeudp.ParseProbe
	_ func(*nativeudp.Session, nativeudp.Probe, func([]byte) error) error            = (*nativeudp.Session).SealWriteProbe
	_ func(*nativeudp.Session, nativeudp.Probe, bool, int, func([]byte) error) error = (*nativeudp.Session).SealWriteAnswer
	_ func(*nativeudp.Hub, veil.DatagramKeys) *nativeudp.Session                     = (*nativeudp.Hub).Register
	_ func(*nativeudp.Hub) nativeudp.Stats                                           = (*nativeudp.Hub).Stats
	_ func(s5server.Config) error                                                    = s5server.ValidateConfig
	_ func(s5server.Config) (*s5server.Server, error)                                = s5server.NewServer
	_ func(tlsdecoy.Config) (*tlsdecoy.Listener, error)                              = tlsdecoy.NewListener
	_ func(ws.UpgraderOpts) *ws.Upgrader                                             = ws.NewUpgrader
	_                                                                                = map[s5server.Telemetry]struct{}{}
)

func TestV230AnswerSize(t *testing.T) {
	var answerSize func([]byte) (int, bool) = nativeudp.AnswerSize //nolint:staticcheck // Verify the deprecated v2.3.0 API.
	for _, tc := range []struct {
		data     []byte
		size     int
		extended bool
	}{
		{nil, 0, false},
		{[]byte{0xff}, 0, false},
		{[]byte{0, 0}, 0, true},
		{[]byte{0x05, 0x78}, 1400, true},
		{[]byte{0xff, 0xff, 0x4d, 0x54, 0x55, 0x32, 0, 0, 0, 1, 0x05, 0x78}, 65535, true},
	} {
		size, extended := answerSize(tc.data)
		if size != tc.size || extended != tc.extended {
			t.Errorf("AnswerSize(%x) = (%d, %v), want (%d, %v)", tc.data, size, extended, tc.size, tc.extended)
		}
	}
}

func TestV230ManualTelemetry(t *testing.T) {
	counter, upDown := noop.Int64Counter{}, noop.Int64UpDownCounter{}
	observable, gauge := noop.Int64ObservableCounter{}, noop.Int64ObservableGauge{}
	legacy := s5server.Telemetry{
		ActiveConnections: upDown, TotalConnections: counter, AuthFailures: counter,
		BytesIn: counter, BytesOut: counter, ObfsFailures: counter,
		ObfsBytesBeforeFailure: noop.Int64Histogram{}, ObfsClockSkew: counter,
		PhaseDuration: noop.Float64Histogram{}, ConnectionsInPhase: upDown, BuildInfo: upDown,
		AuthVerifications: counter, AuthAccountAlerts: counter, HalfCloseFailures: counter,
		ConnectionsRejected: counter, ClientConnections: counter, Sessions: gauge, SessionTransitions: counter,
		NativeUDPPackets: observable, NativeUDPSessions: gauge, NativeUDPDatagrams: observable,
		NativeUDPRouteEvents: observable, NativeUDPStreamDrops: observable, UDPReceiveDrops: observable,
		UDPAssociationsEnded: counter, ConnectionsEnded: counter, DialOutcomes: counter, UDPEgressRotations: counter,
		LogLines: observable, LogDropped: observable,
	}
	copy := legacy
	if legacy != copy {
		t.Fatal("copying telemetry changed equality")
	}
	cfg := s5server.DefaultConfig()
	cfg.RequireAuth = false
	cfg.Telemetry = &legacy
	cfg.Logger = slog.New(slog.DiscardHandler)
	if _, err := s5server.NewServer(cfg); err != nil {
		t.Fatalf("NewServer with only v2.3.0 metrics: %v", err)
	}
	legacy.RecordBuildInfo("fixture", "go", []string{"plain"})
}

type buildInfoCounter struct {
	noop.Int64UpDownCounter
	calls atomic.Int64
}

func (c *buildInfoCounter) Add(_ context.Context, v int64, _ ...metric.AddOption) {
	c.calls.Add(v)
}

func telemetryWithReader(t *testing.T) (*s5server.Telemetry, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	tel, err := s5server.InitTelemetry(provider)
	if err != nil {
		t.Fatal(err)
	}
	return tel, reader
}

func readBuildInfo(t *testing.T, reader *sdkmetric.ManualReader) map[[3]string]int64 {
	t.Helper()
	var collected metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &collected); err != nil {
		t.Fatal(err)
	}
	for _, scope := range collected.ScopeMetrics {
		for _, series := range scope.Metrics {
			if series.Name != "s5core_build_info" {
				continue
			}
			sum, ok := series.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("unexpected build info metric data: %T", series.Data)
			}
			values := make(map[[3]string]int64, len(sum.DataPoints))
			for _, point := range sum.DataPoints {
				version, _ := point.Attributes.Value(attribute.Key("version"))
				goVersion, _ := point.Attributes.Value(attribute.Key("go_version"))
				transports, _ := point.Attributes.Value(attribute.Key("transports"))
				values[[3]string{version.AsString(), goVersion.AsString(), transports.AsString()}] = point.Value
			}
			return values
		}
	}
	t.Fatal("build info metric not collected")
	return nil
}

func TestV230TelemetryCopiesShareBuildInfoDeduplication(t *testing.T) {
	tel, reader := telemetryWithReader(t)
	copied := *tel
	want := map[[3]string]int64{
		{"fixture", "go", "plain"}:  1,
		{"other", "go", "plain"}:    1,
		{"fixture", "new", "plain"}: 1,
		{"fixture", "go", "ws"}:     1,
	}
	var wg sync.WaitGroup
	for _, value := range []*s5server.Telemetry{tel, &copied} {
		for labels := range want {
			for range 8 {
				wg.Go(func() { value.RecordBuildInfo(labels[0], labels[1], []string{labels[2]}) })
			}
		}
	}
	wg.Wait()
	if got := readBuildInfo(t, reader); !maps.Equal(got, want) {
		t.Fatalf("build info = %v, want %v", got, want)
	}
	if *tel != copied {
		t.Fatal("recording build info changed telemetry equality")
	}
}

func TestV230ReplacingBuildInfoDoesNotAffectTheOriginal(t *testing.T) {
	tel, reader := telemetryWithReader(t)
	copied := *tel
	counter := new(buildInfoCounter)
	copied.BuildInfo = counter
	copied.RecordBuildInfo("fixture", "go", []string{"plain"})
	tel.RecordBuildInfo("fixture", "go", []string{"plain"})
	copied.RecordBuildInfo("fixture", "go", []string{"plain"})
	if got := counter.calls.Load(); got != 2 {
		t.Fatalf("replacement count = %d, want 2", got)
	}
	want := map[[3]string]int64{{"fixture", "go", "plain"}: 1}
	if got := readBuildInfo(t, reader); !maps.Equal(got, want) {
		t.Fatalf("original build info = %v, want %v", got, want)
	}
}

func TestV230ManualBuildInfoIsAdditive(t *testing.T) {
	counter := new(buildInfoCounter)
	tel := s5server.Telemetry{BuildInfo: counter}
	for range 3 {
		tel.RecordBuildInfo("fixture", "go", nil)
	}
	if got := counter.calls.Load(); got != 3 {
		t.Fatalf("manual build info count = %d, want 3", got)
	}
}
