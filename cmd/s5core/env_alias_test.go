package main

import (
	"testing"

	"github.com/caarlos0/env/v11"
)

// The client reads PROXY_PASS, the server reads PROXY_PASSWORD, and the same
// .env file travels between them. The server used to refuse to start with a
// message naming PROXY_PASSWORD, which is exactly the name the operator
// believed they had set.
func TestTheClientsNameForThePasswordIsAccepted(t *testing.T) {
	tests := []struct {
		name     string
		password string
		alias    string
		want     string
	}{
		{"only the alias is set", "", "from-alias", "from-alias"},
		{"the canonical name wins", "canonical", "from-alias", "canonical"},
		{"an empty alias changes nothing", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PROXY_PASSWORD", tt.password)
			t.Setenv("PROXY_PASS", tt.alias)

			var cfg params
			if err := env.Parse(&cfg); err != nil {
				t.Fatalf("parse env: %v", err)
			}
			applyEnvAliases(&cfg)

			if cfg.Password != tt.want {
				t.Errorf("password is %q, want %q", cfg.Password, tt.want)
			}
		})
	}
}

// A server that gets its password under the client's name still starts, which
// is the whole point of accepting the alias.
func TestAServerStartsWithTheAliasedPassword(t *testing.T) {
	t.Setenv("PROXY_USER", "operator")
	t.Setenv("PROXY_PASS", "from-alias")

	var cfg params
	if err := env.Parse(&cfg); err != nil {
		t.Fatalf("parse env: %v", err)
	}
	applyEnvAliases(&cfg)
	cfg.Port = "0"

	if _, err := setupServer(cfg, nil, nil); err != nil {
		t.Fatalf("the server refused a password given as PROXY_PASS: %v", err)
	}
}
