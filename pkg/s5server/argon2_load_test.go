//go:build loadtest

// Ф2-5: what the target configuration costs.
//
// The field numbers (0.174s to first byte, 12.5 MB/s) were taken in legacy
// mode, with PROXY_USER/PROXY_PASSWORD - a plain string comparison. The
// documented target configuration is USERS_FILE, where every single SOCKS5
// login runs Argon2id at 64 MiB and three passes. That path had never been
// measured under load, so the cost of the documented migration was unknown.
//
// This file measures both configurations side by side on the same machine, so
// the difference between the columns is the KDF and nothing else. It is build
// tagged because it deliberately burns CPU and gigabytes of RAM:
//
//	go test -tags loadtest -run TestArgon2idCostOfTargetConfiguration -timeout 20m ./pkg/s5server/
//
// Knobs: LOAD_BURST (default 10), LOAD_RATE (100/s), LOAD_SECONDS (10).

package s5server

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/passwordhash"
	"github.com/mazixs/S5Core/internal/userstore"
)

const (
	loadUser = "loaduser"
	loadPass = "load-password-1234"
)

// readRSS returns the resident set size of this process in bytes.
func readRSS(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("parse VmRSS: %v", err)
		}
		return kb * 1024
	}
	t.Fatal("VmRSS not found in /proc/self/status")
	return 0
}

// rssSampler polls RSS while a scenario runs. Peak RSS is the number that
// decides whether the target configuration fits in the server's RAM; the
// average hides exactly the spike that kills it.
type rssSampler struct {
	peak atomic.Uint64
	stop chan struct{}
	done chan struct{}
}

func startRSSSampler(t *testing.T) *rssSampler {
	t.Helper()
	s := &rssSampler{stop: make(chan struct{}), done: make(chan struct{})}
	s.peak.Store(readRSS(t))
	go func() {
		defer close(s.done)
		tick := time.NewTicker(2 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-tick.C:
				rss := readRSS(t)
				for {
					old := s.peak.Load()
					if rss <= old || s.peak.CompareAndSwap(old, rss) {
						break
					}
				}
			}
		}
	}()
	return s
}

func (s *rssSampler) finish() uint64 {
	close(s.stop)
	<-s.done
	return s.peak.Load()
}

// cpuTime returns the process CPU time (user + system).
func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		t.Fatalf("getrusage: %v", err)
	}
	tv := func(v syscall.Timeval) time.Duration {
		return time.Duration(v.Sec)*time.Second + time.Duration(v.Usec)*time.Microsecond
	}
	return tv(ru.Utime) + tv(ru.Stime)
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split port: %v", err)
	}
	_ = l.Close()
	return port
}

// argon2UsersFile writes a users.json holding one account whose password is
// stored as an Argon2id hash - the documented target configuration.
func argon2UsersFile(t *testing.T) string {
	t.Helper()
	hash, err := passwordhash.Hash(loadPass)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	uf := userstore.UsersFile{
		Users: []userstore.UserAccount{{
			ID:           "load-001",
			Username:     loadUser,
			PasswordHash: hash,
			Enabled:      true,
		}},
	}
	data, err := json.MarshalIndent(uf, "", "  ")
	if err != nil {
		t.Fatalf("marshal users file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}
	return path
}

// startLoadServer brings up a server in one of the two credential modes.
// Everything else - fail2ban, timeouts, buffer sizes - is identical, so the
// only difference between the two runs is how a password is checked.
func startLoadServer(t *testing.T, argon2 bool) string {
	t.Helper()
	port := freePort(t)
	cfg := DefaultConfig()
	cfg.Port = port
	cfg.ListenIP = "127.0.0.1"
	cfg.RequireAuth = true
	if argon2 {
		cfg.UsersFile = argon2UsersFile(t)
	}
	srv := startServer(t, cfg)
	if !argon2 {
		if err := srv.AddUser(loadUser, loadPass); err != nil {
			t.Fatalf("add legacy user: %v", err)
		}
	}
	return net.JoinHostPort("127.0.0.1", port)
}

// oneConnection performs a full login and round trip, returning the time to
// the first echoed byte - the number a user actually feels.
func oneConnection(proxyAddr, echoAddr string) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return 0, err
	}
	if err := socks5Connect(conn, loadUser, loadPass, echoAddr); err != nil {
		return 0, err
	}
	if _, err := conn.Write([]byte{'p'}); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	return time.Since(start), nil
}

type loadResult struct {
	scenario  string
	mode      string
	attempted int
	succeeded int
	firstErr  string
	ttfb      []time.Duration
	peakRSS   uint64
	baseRSS   uint64
	cpu       time.Duration
	wall      time.Duration
}

func (r loadResult) pct(p float64) time.Duration {
	if len(r.ttfb) == 0 {
		return 0
	}
	idx := int(float64(len(r.ttfb)-1) * p)
	return r.ttfb[idx]
}

func (r loadResult) row() string {
	mb := func(b uint64) string { return fmt.Sprintf("%.0f MiB", float64(b)/(1024*1024)) }
	ms := func(d time.Duration) string { return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000) }
	perConn := time.Duration(0)
	if r.succeeded > 0 {
		perConn = r.cpu / time.Duration(r.succeeded)
	}
	return fmt.Sprintf("| %s | %s | %d/%d | %s | %s | %s | %s | %s | %s |",
		r.scenario, r.mode, r.succeeded, r.attempted,
		ms(r.pct(0.5)), ms(r.pct(0.95)), ms(r.pct(1)),
		mb(r.peakRSS-r.baseRSS), mb(r.peakRSS), ms(perConn))
}

// runBurst opens n connections at the same instant. A browser opening a page
// does exactly this, six to ten times over.
func runBurst(t *testing.T, mode, proxyAddr, echoAddr string, n int) loadResult {
	t.Helper()
	res := loadResult{scenario: fmt.Sprintf("burst of %d", n), mode: mode, attempted: n}
	res.baseRSS = readRSS(t)
	sampler := startRSSSampler(t)
	cpuStart := cpuTime(t)

	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	wall := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			d, err := oneConnection(proxyAddr, echoAddr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if res.firstErr == "" {
					res.firstErr = err.Error()
				}
				return
			}
			res.succeeded++
			res.ttfb = append(res.ttfb, d)
		}()
	}
	close(start)
	wg.Wait()

	res.wall = time.Since(wall)
	res.cpu = cpuTime(t) - cpuStart
	res.peakRSS = sampler.finish()
	sort.Slice(res.ttfb, func(i, j int) bool { return res.ttfb[i] < res.ttfb[j] })
	return res
}

// runRate opens connections at a steady rate for the given duration, without
// waiting for the previous ones to finish - the shape of real arrivals.
func runRate(t *testing.T, mode, proxyAddr, echoAddr string, perSecond int, d time.Duration) loadResult {
	t.Helper()
	res := loadResult{
		scenario: fmt.Sprintf("%d conn/s for %s", perSecond, d),
		mode:     mode,
	}
	res.baseRSS = readRSS(t)
	sampler := startRSSSampler(t)
	cpuStart := cpuTime(t)

	var mu sync.Mutex
	var wg sync.WaitGroup
	interval := time.Second / time.Duration(perSecond)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	deadline := time.Now().Add(d)
	wall := time.Now()
	for time.Now().Before(deadline) {
		<-tick.C
		res.attempted++
		wg.Add(1)
		go func() {
			defer wg.Done()
			dur, err := oneConnection(proxyAddr, echoAddr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if res.firstErr == "" {
					res.firstErr = err.Error()
				}
				return
			}
			res.succeeded++
			res.ttfb = append(res.ttfb, dur)
		}()
	}
	wg.Wait()

	res.wall = time.Since(wall)
	res.cpu = cpuTime(t) - cpuStart
	res.peakRSS = sampler.finish()
	sort.Slice(res.ttfb, func(i, j int) bool { return res.ttfb[i] < res.ttfb[j] })
	return res
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func TestArgon2idCostOfTargetConfiguration(t *testing.T) {
	burst := envInt("LOAD_BURST", 10)
	rate := envInt("LOAD_RATE", 100)
	seconds := envInt("LOAD_SECONDS", 10)

	echoAddr := startEchoServer(t)

	var results []loadResult
	for _, mode := range []struct {
		name   string
		argon2 bool
	}{
		{"legacy plaintext", false},
		{"USERS_FILE + Argon2id", true},
	} {
		proxyAddr := startLoadServer(t, mode.argon2)

		// One warm-up connection, so the first measured login does not pay
		// for lazy initialisation.
		if _, err := oneConnection(proxyAddr, echoAddr); err != nil {
			t.Fatalf("%s: warm-up connection: %v", mode.name, err)
		}

		results = append(results,
			runBurst(t, mode.name, proxyAddr, echoAddr, burst),
			runRate(t, mode.name, proxyAddr, echoAddr, rate, time.Duration(seconds)*time.Second),
		)
	}

	var b strings.Builder
	b.WriteString("\n| Scenario | Mode | OK/total | TTFB p50 | p95 | max | peak RSS over idle | peak RSS | CPU per conn |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		b.WriteString(r.row() + "\n")
	}
	for _, r := range results {
		if r.firstErr != "" {
			b.WriteString(fmt.Sprintf("\n%s / %s: first failure: %s", r.scenario, r.mode, r.firstErr))
		}
	}
	t.Log(b.String())

	for _, r := range results {
		if r.succeeded == 0 {
			t.Fatalf("%s / %s: no connection succeeded (%s)", r.scenario, r.mode, r.firstErr)
		}
	}
}
