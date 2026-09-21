package main

import (
	"strings"
	"testing"

	"github.com/caarlos0/env/v11"
)

// TRANSPORT_ADVICE is the operator's lever for plan task Ф5-7. It has to
// reach the server from the environment, and a typo in it has to stop the
// server at startup with the variable named - a server that started and
// quietly advised nothing would leave the operator believing the fleet was
// moving.
func TestTransportAdviceComesFromTheEnvironment(t *testing.T) {
	t.Setenv("OBFS_ENABLED", "true")
	t.Setenv("OBFS_PSK", "01234567890123456789012345678901")
	t.Setenv("REQUIRE_AUTH", "false")

	t.Run("a valid advice starts the server", func(t *testing.T) {
		t.Setenv("TRANSPORT_ADVICE", "obfs padding=64 keepalive=10s-20s")
		var cfg params
		if err := env.Parse(&cfg); err != nil {
			t.Fatalf("parse env: %v", err)
		}
		cfg.Port = "0"
		if _, err := setupServer(cfg, nil, nil); err != nil {
			t.Fatalf("the server refused a valid TRANSPORT_ADVICE: %v", err)
		}
	})

	t.Run("a typo stops the server and is named", func(t *testing.T) {
		t.Setenv("TRANSPORT_ADVICE", "obfs paddng=64")
		var cfg params
		if err := env.Parse(&cfg); err != nil {
			t.Fatalf("parse env: %v", err)
		}
		cfg.Port = "0"
		_, err := setupServer(cfg, nil, nil)
		if err == nil {
			t.Fatal("the server started with an unparsable TRANSPORT_ADVICE")
		}
		if !strings.Contains(err.Error(), "TRANSPORT_ADVICE") || !strings.Contains(err.Error(), "paddng") {
			t.Fatalf("the error names neither the variable nor the typo: %v", err)
		}
	})

	t.Run("a transport the server does not run is refused", func(t *testing.T) {
		t.Setenv("TRANSPORT_ADVICE", "ws")
		var cfg params
		if err := env.Parse(&cfg); err != nil {
			t.Fatalf("parse env: %v", err)
		}
		cfg.Port = "0"
		_, err := setupServer(cfg, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "WS_ENABLED") {
			t.Fatalf("an advice to a disabled listener was accepted or the error does not say why: %v", err)
		}
	})
}
