package s5server

import (
	"strings"
	"testing"

	"go.opentelemetry.io/otel/metric/noop"
)

// A Telemetry is a struct of interfaces. Handing the server one that was
// assembled by hand - or kept from an older version that had fewer fields -
// used to start fine and panic on the first connection that touched a field
// nobody filled in. The mistake is made where configuration is written, so it
// is answered there.
func TestAPartlyBuiltTelemetryIsAConfigurationError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Telemetry = &Telemetry{
		// The two fields a hand-written Telemetry usually has, and no others.
		ActiveConnections: noop.Int64UpDownCounter{},
		TotalConnections:  noop.Int64Counter{},
	}

	err := ValidateConfig(cfg)
	if err == nil {
		t.Fatal("a Telemetry with unset instruments was accepted")
	}
	if !strings.Contains(err.Error(), "Telemetry.") || !strings.Contains(err.Error(), "InitTelemetry") {
		t.Errorf("the error does not say which field is missing or how to build one: %v", err)
	}

	if _, err := NewServer(cfg); err == nil {
		t.Error("NewServer accepted a configuration ValidateConfig rejects")
	}
}

// The counterpart: telemetry is optional, and a Telemetry from InitTelemetry
// is complete. Without this, the check above would pass on a rule that simply
// refuses every Telemetry.
func TestTelemetryFromInitTelemetryIsAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireAuth = false

	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("a configuration without telemetry was rejected: %v", err)
	}

	tel, err := InitTelemetry(noop.NewMeterProvider())
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}
	cfg.Telemetry = tel
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("a Telemetry built by InitTelemetry was rejected: %v", err)
	}
}
