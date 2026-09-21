package s5server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/socks5"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// phaseSums is one snapshot of the phase histogram: total seconds and count
// per phase, summed over outcomes.
type phaseSums struct {
	seconds map[string]float64
	count   map[string]uint64
	inPhase map[string]int64
}

func collectPhases(t *testing.T, reader sdkmetric.Reader) phaseSums {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	out := phaseSums{
		seconds: map[string]float64{},
		count:   map[string]uint64{},
		inPhase: map[string]int64{},
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "s5core_connection_phase_seconds":
				hist, ok := m.Data.(metricdata.Histogram[float64])
				if !ok {
					t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
				}
				for _, dp := range hist.DataPoints {
					phase := requirePhaseLabels(t, m.Name, dp.Attributes, true)
					out.seconds[phase] += dp.Sum
					out.count[phase] += dp.Count
				}
			case "s5core_connections_in_phase":
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
				}
				for _, dp := range sum.DataPoints {
					phase := requirePhaseLabels(t, m.Name, dp.Attributes, false)
					out.inPhase[phase] += dp.Value
				}
			}
		}
	}
	return out
}

// requirePhaseLabels enforces docs/design/observability-policy.md on the phase
// instruments: phase (and outcome, where applicable) and nothing else.
func requirePhaseLabels(t *testing.T, metricName string, set attribute.Set, withOutcome bool) string {
	t.Helper()
	want := 1
	if withOutcome {
		want = 2
	}
	var phase string
	n := 0
	iter := set.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		n++
		key, value := string(kv.Key), kv.Value.Emit()
		switch {
		case key == "phase":
			phase = value
		case key == "outcome" && withOutcome:
			if value != "ok" && value != "fail" {
				t.Errorf("%s: unexpected outcome %q", metricName, value)
			}
		default:
			t.Errorf("%s: label %q=%q is not allowed", metricName, key, value)
		}
	}
	if n != want {
		t.Errorf("%s: expected %d labels, got %d", metricName, want, n)
	}
	if phase == "" {
		t.Errorf("%s: missing phase label", metricName)
	}
	return phase
}

// TestPhaseMetricsExplainTimeToFirstByte is the acceptance check for plan task
// Ф1-3: the measured phases must account for the latency a client actually
// sees, with a small remainder. Whatever is left over is the next thing worth
// optimising - and now it has an address instead of being a guess.
func TestPhaseMetricsExplainTimeToFirstByte(t *testing.T) {
	const budget = 20 * time.Millisecond

	echoAddr := startEchoServer(t)
	usersPath := testUsersFile(t)

	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	const plainPort = "19081"
	startServer(t, Config{
		Port:            plainPort,
		ListenIP:        "127.0.0.1",
		RequireAuth:     true,
		UsersFile:       usersPath,
		Fail2BanRetries: 10,
		Fail2BanTime:    time.Minute,
		Telemetry:       telemetry,
	})

	// Первое соединение переводит пароль из plaintext в Argon2id, поэтому оно
	// не показательно: измеряем второе, когда хранилище уже в рабочем виде.
	if _, err := timeToFirstByte(t, plainPort, echoAddr); err != nil {
		t.Fatalf("warm-up connection: %v", err)
	}
	// Соединение закрывается на стороне клиента, а фаза session закрывается на
	// стороне сервера: без ожидания снимок поймает половину предыдущей сессии.
	waitPhasesIdle(t, reader)
	before := collectPhases(t, reader)

	observed, err := timeToFirstByte(t, plainPort, echoAddr)
	if err != nil {
		t.Fatalf("measured connection: %v", err)
	}
	waitPhasesIdle(t, reader)
	after := collectPhases(t, reader)

	var explained float64
	for _, phase := range []socks5.Phase{
		socks5.PhaseHandshake, socks5.PhaseAuth, socks5.PhaseDial, socks5.PhaseFirstByte,
	} {
		name := string(phase)
		delta := after.seconds[name] - before.seconds[name]
		if after.count[name]-before.count[name] != 1 {
			t.Errorf("phase %q: got %d observations for one connection, want 1",
				name, after.count[name]-before.count[name])
		}
		t.Logf("phase %-11s %v", name, time.Duration(delta*float64(time.Second)).Round(time.Microsecond))
		explained += delta
	}

	// Сессия измеряется отдельно и не складывается с остальными: она их
	// включает и длится до закрытия соединения.
	if after.count[string(socks5.PhaseSession)]-before.count[string(socks5.PhaseSession)] != 1 {
		t.Errorf("phase session: expected exactly one observation per connection")
	}

	explainedDur := time.Duration(explained * float64(time.Second))
	remainder := observed - explainedDur
	t.Logf("observed by client %v, explained by phases %v, remainder %v",
		observed.Round(time.Microsecond), explainedDur.Round(time.Microsecond), remainder.Round(time.Microsecond))

	if remainder < 0 {
		// Фазы не могут в сумме превышать наблюдаемое время больше, чем на
		// погрешность измерения: иначе они пересекаются и разложение неверно.
		if -remainder > time.Millisecond {
			t.Errorf("phases sum to %v, more than the %v the client observed: the phases overlap",
				explainedDur, observed)
		}
	} else if remainder > budget {
		t.Errorf("phases explain only %v of the %v the client observed, remainder %v exceeds the %v budget",
			explainedDur, observed, remainder, budget)
	}

}

// waitPhasesIdle blocks until no connection is counted in any phase, which is
// also the check that the phase counter is balanced: every enter has a leave.
func waitPhasesIdle(t *testing.T, reader sdkmetric.Reader) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		leftover := collectPhases(t, reader).inPhase
		busy := false
		for _, v := range leftover {
			if v != 0 {
				busy = true
			}
		}
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("connections still counted in phases after close: %v", leftover)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// timeToFirstByte measures what a client sees: from opening the TCP connection
// to receiving the first byte the destination echoes back.
func timeToFirstByte(t *testing.T, proxyPort, targetAddr string) (time.Duration, error) {
	t.Helper()
	start := time.Now()

	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+proxyPort, 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := socks5Connect(conn, "alice", "secret1", targetAddr); err != nil {
		return 0, err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return 0, err
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
