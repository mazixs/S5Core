package s5server

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func waitServerRun(t *testing.T, s *Server, ready bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		s.lifeMu.Lock()
		running := s.running
		s.lifeMu.Unlock()
		if running && (!ready || len(s.allPipelines()) > 0) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("server did not enter Start")
}

func TestConcurrentStopDuringStartAndRepeatedStart(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	tel, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{Port: "0", ListenIP: "127.0.0.1", Telemetry: tel, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 20; round++ {
		done := make(chan error, 1)
		go func() { done <- s.Start(context.Background()) }()
		waitServerRun(t, s, round%2 == 0)
		if err := s.Start(context.Background()); err == nil {
			t.Fatal("overlapping Start was accepted")
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := s.Stop(); err != nil {
					t.Errorf("Stop: %v", err)
				}
			}()
		}
		wg.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Start did not finish")
		}
		if s.openSessions() != 0 {
			t.Fatal("sessions remain after Stop")
		}
	}
	if got := counterValue(t, reader, "s5core_build_info"); got != 1 {
		t.Fatalf("build info=%d, want 1", got)
	}
}
