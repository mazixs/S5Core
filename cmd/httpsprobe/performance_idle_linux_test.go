package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"
	"uuid"
)

// perfPostWindow is how long the latency recorder goes on recording after a
// marker; it writes the incident's manifest after that.
const perfPostWindow = 90 * time.Second

// perfIdleTunnels holds S5_PERF_IDLE_TUNNELS raw SOCKS TCP tunnels to a local
// echo for S5_PERF_TUNNEL_IDLE_DURATION. No data moves during the hold; the
// proxies' maintenance and the scrapes go on. Each tunnel echoes a byte before
// and after it. It returns how many tunnels it holds and what closes them.
func perfIdleTunnels(t *testing.T, socks string) (int, func()) {
	t.Helper()
	n := perfInt("S5_PERF_IDLE_TUNNELS", 8)
	if n > 128 {
		t.Fatal("S5_PERF_IDLE_TUNNELS must be at most 128")
	}
	hold := perfDuration("S5_PERF_TUNNEL_IDLE_DURATION", 2*time.Minute)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var peers, conns []net.Conn
	var accept, handlers sync.WaitGroup
	accept.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			peers = append(peers, conn)
			handlers.Go(func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			})
		}
	})
	release := sync.OnceFunc(func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
		_ = listener.Close()
		accept.Wait()
		// Accept has returned, so no peer comes after this.
		for _, conn := range peers {
			_ = conn.Close()
		}
		handlers.Wait()
	})
	t.Cleanup(release)
	tr, err := newTransport(socks, nil, true, false, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		conn, err := tr.DialContext(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		if err := perfIdleEcho(conn, 0x31); err != nil {
			t.Fatal("before the hold:", err)
		}
	}
	t.Logf("idle tunnels=%d hold=%s", n, hold)
	perfWait(t, hold)
	for _, conn := range conns {
		if err := perfIdleEcho(conn, 0x72); err != nil {
			t.Fatal("after the hold:", err)
		}
	}
	return n, release
}

func perfIdleEcho(conn net.Conn, value byte) error {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{value}); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != value {
		return fmt.Errorf("echo %#x, sent %#x", reply[0], value)
	}
	return conn.SetDeadline(time.Time{})
}

func perfWait(t *testing.T, d time.Duration) {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
}

// perfRecoveryWait waits out a recovery period. With S5_PERF_RECOVERY_MARKERS
// its last 90 seconds are a manual incident of the latency recorder of every
// proxy in endpoints, the subdirectories of dir; it returns the incident's ID
// once each recorder has saved it.
func perfRecoveryWait(t *testing.T, dir string, endpoints []string, d time.Duration) string {
	t.Helper()
	if os.Getenv("S5_PERF_RECOVERY_MARKERS") != "1" || len(endpoints) == 0 {
		perfWait(t, d)
		return ""
	}
	if d < perfPostWindow {
		t.Fatal("S5_PERF_RECOVERY_MARKERS needs S5_PERF_RECOVERY_DURATION of at least 90s")
	}
	perfWait(t, d-perfPostWindow)
	id := uuid.New().String()
	marker, err := json.Marshal(map[string]string{"incident_id": id})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range endpoints {
		// Renamed into place: the recorder must not read a marker half written.
		path := filepath.Join(dir, endpoint, "diagnostics", "trigger.json")
		if err := os.WriteFile(path+".tmp", marker, 0600); err != nil {
			t.Fatal("no latency diagnostics directory:", err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
	}
	// A recorder takes the marker within a second, but writes the manifest
	// only after the post window.
	deadline := time.Now().Add(perfPostWindow + 10*time.Second)
	for {
		saved := 0
		for _, endpoint := range endpoints {
			if _, err := os.Stat(filepath.Join(dir, endpoint, "diagnostics", id+".manifest.json")); err == nil {
				saved++
			}
		}
		if saved == len(endpoints) {
			return id
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery incident %s saved by %d of %d proxies", id, saved, len(endpoints))
		}
		perfWait(t, 250*time.Millisecond)
	}
}

// The hold on direct loopback: the same connections echo after it.
func TestPerformanceIdleTunnels(t *testing.T) {
	t.Setenv("S5_PERF_IDLE_TUNNELS", "2")
	t.Setenv("S5_PERF_TUNNEL_IDLE_DURATION", "50ms")
	started := time.Now()
	held, release := perfIdleTunnels(t, "")
	if held != 2 || time.Since(started) < 50*time.Millisecond {
		t.Fatalf("held %d tunnels for %s", held, time.Since(started))
	}
	release()
}

func TestPerformanceRecoveryMarker(t *testing.T) {
	t.Setenv("S5_PERF_RECOVERY_MARKERS", "1")
	dir := t.TempDir()
	endpoints := []string{"client", "server"}
	for _, endpoint := range endpoints {
		if err := os.MkdirAll(filepath.Join(dir, endpoint, "diagnostics"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	synctest.Test(t, func(t *testing.T) {
		markers := make(chan string, len(endpoints))
		for _, endpoint := range endpoints {
			// A recorder: it polls the marker and saves the incident after the post window.
			go func() {
				path := filepath.Join(dir, endpoint, "diagnostics")
				for {
					data, err := os.ReadFile(filepath.Join(path, "trigger.json"))
					if err == nil {
						var marker struct {
							IncidentID string `json:"incident_id"`
						}
						if err := json.Unmarshal(data, &marker); err != nil {
							t.Error(err)
						}
						markers <- marker.IncidentID
						time.Sleep(perfPostWindow)
						if err := os.WriteFile(filepath.Join(path, marker.IncidentID+".manifest.json"), []byte("{}"), 0600); err != nil {
							t.Error(err)
						}
						return
					}
					time.Sleep(500 * time.Millisecond)
				}
			}()
		}
		started := time.Now()
		id := perfRecoveryWait(t, dir, endpoints, 3*time.Minute)
		if elapsed := time.Since(started); elapsed < 3*time.Minute || elapsed > 3*time.Minute+time.Second {
			t.Fatalf("recovery took %s, not the period with the post window inside it", elapsed)
		}
		for range endpoints {
			if got := <-markers; got != id {
				t.Fatalf("marker %q, incident %q", got, id)
			}
		}
	})
}
