package s5server

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
	"github.com/mazixs/S5Core/internal/userstore"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// collectAuthPaths returns the count of password checks per answering path.
// It also enforces docs/design/observability-policy.md: the only allowed label is
// path, whose values come from a fixed set inside the process.
func collectAuthPaths(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "s5core_auth_verifications_total" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s: unexpected data type %T", m.Name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				out[requireAuthPathLabel(t, m.Name, dp.Attributes)] += dp.Value
			}
		}
	}
	return out
}

func requireAuthPathLabel(t *testing.T, metricName string, set attribute.Set) string {
	t.Helper()
	var path string
	n := 0
	iter := set.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		n++
		key, value := string(kv.Key), kv.Value.Emit()
		if key != "path" {
			t.Errorf("%s: label %q=%q is not allowed", metricName, key, value)
			continue
		}
		switch userstore.VerifyPath(value) {
		case userstore.VerifyPathKDF, userstore.VerifyPathCache, userstore.VerifyPathCoalesced:
			path = value
		default:
			t.Errorf("%s: unexpected path %q", metricName, value)
		}
	}
	if n != 1 {
		t.Errorf("%s: expected exactly one label, got %d", metricName, n)
	}
	return path
}

// argon2UsersFileAt writes a users file with one Argon2id account.
func argon2UsersFileAt(t *testing.T, username, password string) string {
	t.Helper()
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	data, err := json.Marshal(userstore.UsersFile{Users: []userstore.UserAccount{{
		ID:           "u-metrics",
		Username:     username,
		PasswordHash: hash,
		Enabled:      true,
	}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestArgon2idRunsOncePerPasswordNotPerConnection is the acceptance check for
// plan task Ф3-6. Before it, every SOCKS5 login ran Argon2id at 64 MiB: ten
// connections for one browser page meant ten KDF runs, 261 ms to first byte
// and half a gigabyte of RSS (docs/benchmarks/argon2-cost.md). The metric is what makes
// the regression detectable in production rather than only in this test - a
// server whose kdf count tracks its connection count has lost the cache.
func TestArgon2idRunsOncePerPasswordNotPerConnection(t *testing.T) {
	const (
		user     = "metrics-user"
		password = "metrics-password"
		logins   = 10 // one page load
	)

	echoAddr := startEchoServer(t)
	usersPath := argon2UsersFileAt(t, user, password)

	reader := sdkmetric.NewManualReader()
	telemetry, err := InitTelemetry(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	if err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}

	port := "19087"
	startServer(t, Config{
		Port:            port,
		ListenIP:        "127.0.0.1",
		RequireAuth:     true,
		UsersFile:       usersPath,
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
		Fail2BanRetries: 20,
		Fail2BanTime:    time.Minute,
		Telemetry:       telemetry,
	})

	login := func(pass string) error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		return socks5Connect(conn, user, pass, echoAddr)
	}

	for i := 0; i < logins; i++ {
		if err := login(password); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}

	paths := collectAuthPaths(t, reader)
	kdf := paths[string(userstore.VerifyPathKDF)]
	cheap := paths[string(userstore.VerifyPathCache)] + paths[string(userstore.VerifyPathCoalesced)]

	if kdf != 1 {
		t.Fatalf("Argon2id ran %d times for %d logins, want exactly 1", kdf, logins)
	}
	if cheap != logins-1 {
		t.Fatalf("%d logins avoided the KDF, want %d", cheap, logins-1)
	}

	// A wrong password must not reopen the expensive path: otherwise anyone
	// able to open a TCP connection can spend 64 MiB of the server's memory
	// per guess.
	for i := 0; i < 5; i++ {
		if err := login("wrong-password"); err == nil {
			t.Fatal("wrong password was accepted")
		}
	}
	paths = collectAuthPaths(t, reader)
	if got := paths[string(userstore.VerifyPathKDF)]; got != kdf {
		t.Fatalf("wrong passwords triggered %d extra KDF runs, want 0", got-kdf)
	}
}
