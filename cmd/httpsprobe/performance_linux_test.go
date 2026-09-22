package main

// Opt-in process benchmark: origin and generator live here; the actual client
// and server binaries run as separate processes. No external endpoint is used.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
)

type perfUsage struct {
	CPUTicks     uint64 `json:"cpu_ticks"`
	RSSBytes     uint64 `json:"rss_bytes"`
	PeakRSSBytes uint64 `json:"peak_rss_bytes"`
}

func processUsage(t *testing.T, cmd *exec.Cmd) perfUsage {
	t.Helper()
	if cmd == nil {
		return perfUsage{}
	}
	return pidUsage(t, cmd.Process.Pid)
}

func pidUsage(t *testing.T, pid int) perfUsage {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(data)[strings.LastIndex(string(data), ")")+2:])
	u, _ := strconv.ParseUint(f[11], 10, 64)
	s, _ := strconv.ParseUint(f[12], 10, 64)
	result := perfUsage{CPUTicks: u + s}
	data, err = os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "VmRSS:":
			result.RSSBytes = n * 1024
		case "VmHWM:":
			result.PeakRSSBytes = n * 1024
		}
	}
	return result
}
func perfAddr(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	_ = l.Close()
	return a
}
func perfInt(name string, fallback int) int {
	if s := os.Getenv(name); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 {
			panic(name + " must be positive")
		}
		return n
	}
	return fallback
}
func perfList(name, fallback string) []string {
	s := os.Getenv(name)
	if s == "" {
		s = fallback
	}
	return strings.Split(s, ",")
}
func perfProcess(t *testing.T, binary, ready, dir string, env []string) *exec.Cmd {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	log, e := os.Create(filepath.Join(dir, "process.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary)
	// Do not inherit deployment credentials or listener settings.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LOG_LEVEL=error", "GOMAXPROCS=" + strconv.Itoa(perfInt("S5_PERF_PROCS", 16))}, env...)
	if os.Getenv("S5_PERF_TRACE") == "1" {
		cmd.Env = append(cmd.Env, "S5_TRACE=1", "GODEBUG=gctrace=1")
	}
	if os.Getenv("S5_PERF_PROFILE") == "1" {
		cmd.Env = append(cmd.Env, "S5_PROFILE_DIR="+filepath.Join(dir, "profiles"))
	}
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case e := <-done:
			if e != nil {
				t.Errorf("%s exit: %v", filepath.Base(binary), e)
			}
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("process failed graceful shutdown")
		}
		_ = log.Close()
	})
	for i := 0; i < 500; i++ {
		c, e := net.DialTimeout("tcp", ready, 20*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return cmd
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not listen; inspect %s", binary, dir)
	return nil
}
func perfHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestPerformanceProcesses(t *testing.T) {
	serverBin, clientBin, out := os.Getenv("S5_PERF_SERVER"), os.Getenv("S5_PERF_CLIENT"), os.Getenv("S5_PERF_OUT")
	if serverBin == "" || clientBin == "" || out == "" {
		t.Skip("set S5_PERF_SERVER, S5_PERF_CLIENT and fresh S5_PERF_OUT to run process benchmark")
	}
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	cert, key, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(cert)
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		t.Fatal("test CA", err)
	}
	small := []byte("S5Core verified response")
	large := bytes.Repeat([]byte("0123456789abcdef"), 1<<19)
	largeHash := perfHash(large)
	streamChunk := large[:32768]
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(small) })
	mux.HandleFunc("/large", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(large) })
	streamHash := perfHash(bytes.Repeat(streamChunk, 350))
	uploadHandler := func(w http.ResponseWriter, r *http.Request) {
		expectedSize, expectedHash := int64(len(large)), largeHash
		if r.URL.Path == "/upload-stream" {
			expectedSize, expectedHash = int64(len(streamChunk)*350), streamHash
		}
		h := sha256.New()
		n, e := io.Copy(h, r.Body)
		if e != nil || n != expectedSize || hex.EncodeToString(h.Sum(nil)) != expectedHash {
			http.Error(w, "corrupt upload", 400)
			return
		}
		_, _ = w.Write(small)
	}
	mux.HandleFunc("/upload", uploadHandler)
	mux.HandleFunc("/upload-stream", uploadHandler)
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 350; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			if _, e := w.Write(streamChunk); e != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	origin := httptest.NewUnstartedServer(mux)
	origin.EnableHTTP2 = true
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	origin.StartTLS()
	defer origin.Close()
	for _, mode := range perfList("S5_PERF_MODES", "direct,plain,obfs,wss") {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(out, mode)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			plain, obfsAddr, wsAddr, metrics, clientAddr := perfAddr(t), perfAddr(t), perfAddr(t), perfAddr(t), perfAddr(t)
			if a := os.Getenv("S5_PERF_OBFS_ADDR"); a != "" {
				obfsAddr = a
			}
			if a := os.Getenv("S5_PERF_WS_ADDR"); a != "" {
				wsAddr = a
			}
			_, pp, _ := net.SplitHostPort(plain)
			_, op, _ := net.SplitHostPort(obfsAddr)
			_, mp, _ := net.SplitHostPort(metrics)
			psk := "0123456789abcdef0123456789abcdef"
			serverEnv := []string{"PROXY_LISTEN_IP=127.0.0.1", "PROXY_PORT=" + pp, "REQUIRE_AUTH=false", "OBFS_ENABLED=true", "OBFS_PORT=" + op, "OBFS_PSK=" + psk, "OBFS_MAX_PADDING=256", "OBFS_MTU=1400", "WS_ENABLED=true", "WS_ADDR=" + wsAddr, "WS_CERT_FILE=" + cert, "WS_KEY_FILE=" + key, "WS_MIN_FRAME=256", "WS_MAX_FRAME=4096", "METRICS_PORT=" + mp, "METRICS_BIND_ADDR=127.0.0.1", "TRAFFIC_FLUSH_INTERVAL=250ms"}
			clientEnv := []string{"CLIENT_LISTEN_ADDR=" + clientAddr, "SERVER_ADDR=" + obfsAddr, "OBFS_PSK=" + psk, "OBFS_MAX_PADDING=256", "OBFS_MTU=1400", "OBFS_FORMAT=v1", "KEEPALIVE_MIN=10s", "KEEPALIVE_MAX=20s", "TRANSPORT=obfs"}
			if os.Getenv("S5_PERF_TLS_CACHE") == "0" {
				clientEnv = append(clientEnv, "WS_TLS_SESSION_CACHE=false")
			}
			if fp := os.Getenv("S5_PERF_FINGERPRINT"); fp != "" {
				clientEnv = append(clientEnv, "TLS_FINGERPRINT="+fp)
			}
			if n := os.Getenv("S5_PERF_ROUTES"); n != "" {
				count, e := strconv.Atoi(n)
				if e != nil || count < 1 {
					t.Fatal("S5_PERF_ROUTES must be positive")
				}
				patterns := make([]string, count)
				for i := range patterns {
					// Keep 10000 rules below Linux's per-environment-string
					// execve limit; only localhost is ever resolved.
					patterns[i] = fmt.Sprintf("*.r%x.t", i)
				}
				patterns[len(patterns)-1] = "localhost"
				clientEnv = append(clientEnv, "ROUTE_DOMAINS="+strings.Join(patterns, ","))
			}
			if mode == "wss" {
				clientEnv = append(clientEnv, "TRANSPORT=ws", "WS_URL=wss://"+wsAddr+"/ws", "WS_CA_FILE="+cert, "WS_MIN_FRAME=256", "WS_MAX_FRAME=4096")
			}
			if auth := os.Getenv("S5_PERF_AUTH"); auth != "" && mode != "direct" {
				memberKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
				users := filepath.Join(dir, "users.json")
				data := fmt.Sprintf(`{"users":[{"id":"bench","username":"bench","password":"bench-password","enabled":true,"tunnel_key":%q}]}`, memberKey)
				if err := os.WriteFile(users, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				serverEnv = append(serverEnv, "USERS_FILE="+users, "REQUIRE_AUTH=true")
				switch auth {
				case "member":
					clientEnv = append(clientEnv, "PROXY_AUTH_MODE=member-only", "OBFS_MEMBER_ID=bench", "OBFS_MEMBER_KEY="+memberKey)
				case "fallback":
					clientEnv = append(clientEnv, "PROXY_AUTH_MODE=password-fallback", "OBFS_MEMBER_ID=bench", "OBFS_MEMBER_KEY="+memberKey, "PROXY_USER=bench", "PROXY_PASS=bench-password")
				case "password":
					clientEnv = append(clientEnv, "PROXY_USER=bench", "PROXY_PASS=bench-password")
				default:
					t.Fatal("unknown S5_PERF_AUTH")
				}
			}
			if n := os.Getenv("S5_PERF_WS_MAX_FRAME"); n != "" {
				serverEnv = append(serverEnv, "WS_MAX_FRAME="+n)
				clientEnv = append(clientEnv, "WS_MAX_FRAME="+n)
			}
			var server, client *exec.Cmd
			socks := ""
			if mode != "direct" {
				server = perfProcess(t, serverBin, plain, filepath.Join(dir, "server"), serverEnv)
				socks = plain
			}
			if mode == "obfs" || mode == "wss" {
				client = perfProcess(t, clientBin, clientAddr, filepath.Join(dir, "client"), clientEnv)
				socks = clientAddr
			}
			// Real Prometheus scrapes run alongside requests. The server uses its SDK.
			scrapeCtx, cancelScrape := context.WithCancel(context.Background())
			var scrapeWG sync.WaitGroup
			if server != nil {
				scrapeWG.Go(func() {
					hc := &http.Client{Timeout: time.Second}
					ticker := time.NewTicker(250 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-scrapeCtx.Done():
							return
						case <-ticker.C:
							resp, e := hc.Get("http://" + metrics + "/metrics")
							if e == nil {
								_, _ = io.Copy(io.Discard, resp.Body)
								_ = resp.Body.Close()
							}
						}
					}
				})
			}
			defer func() { cancelScrape(); scrapeWG.Wait() }()
			results, e := os.Create(filepath.Join(dir, "requests.jsonl"))
			if e != nil {
				t.Fatal(e)
			}
			defer results.Close()
			enc := json.NewEncoder(results)
			usage, e := os.Create(filepath.Join(dir, "resources.jsonl"))
			if e != nil {
				t.Fatal(e)
			}
			defer usage.Close()
			ue := json.NewEncoder(usage)
			for _, protocol := range perfList("S5_PERF_PROTOCOLS", "h1,h2") {
				for _, reuseMode := range perfList("S5_PERF_REUSE", "new,reuse") {
					for _, scenario := range perfList("S5_PERF_CASES", "small,large,upload") {
						h2, reuse := protocol == "h2", reuseMode == "reuse"
						tr, e := newTransport(socks, roots, reuse, h2, 5*time.Second)
						if e != nil {
							t.Fatal(e)
						}
						tr.MaxIdleConnsPerHost = perfInt("S5_PERF_CONCURRENCY", 1)
						target := origin.URL
						if os.Getenv("S5_PERF_FQDN") == "1" {
							target = strings.Replace(target, "127.0.0.1", "localhost", 1)
							tr.TLSClientConfig.ServerName = "127.0.0.1"
						}
						hc := &http.Client{Transport: tr, Timeout: 70 * time.Second}
						path := scenario
						if scenario == "mixed" {
							path = "small"
						}
						want := small
						count := perfInt("S5_PERF_SMALL", 100)
						switch scenario {
						case "large":
							want = large
							count = perfInt("S5_PERF_LARGE", 15)
						case "upload":
							count = perfInt("S5_PERF_LARGE", 15)
						case "upload-stream":
							count = 1
						case "stream":
							want = bytes.Repeat(streamChunk, 350)
							count = 1
						}
						expected := perfHash(want)
						one := func() measurement {
							if scenario == "upload-stream" {
								reader, writer := io.Pipe()
								done := make(chan error, 1)
								go func() {
									defer writer.Close()
									for i := 0; i < 350; i++ {
										time.Sleep(100 * time.Millisecond)
										if _, e := writer.Write(streamChunk); e != nil {
											done <- e
											return
										}
									}
									done <- nil
								}()
								m := measureBody(context.Background(), hc, target+"/upload-stream", http.MethodPost, reader)
								_ = reader.Close()
								if e := <-done; e != nil && m.Error == "" {
									m.Error = e.Error()
								}
								return m
							}

							if scenario == "upload" {
								return measureBody(context.Background(), hc, target+"/upload", http.MethodPost, bytes.NewReader(large))
							}
							return measure(context.Background(), hc, target+"/"+path)
						}
						for i := 0; i < 3 && scenario != "stream" && scenario != "upload-stream"; i++ {
							m := one()
							if m.Error != "" || m.Status != 200 || m.SHA256 != expected {
								t.Fatalf("warmup: %+v", m)
							}
						}
						beforeS, beforeC := processUsage(t, server), processUsage(t, client)
						beforeG := pidUsage(t, os.Getpid())
						start := time.Now()
						bgCtx, stopBG := context.WithCancel(context.Background())
						var bg sync.WaitGroup
						if scenario == "mixed" {
							bg.Go(func() {
								bt, e := newTransport(socks, roots, true, h2, 5*time.Second)
								if e != nil {
									t.Error(e)
									return
								}
								defer bt.CloseIdleConnections()
								bc := &http.Client{Transport: bt, Timeout: 30 * time.Second}
								for bgCtx.Err() == nil {
									m := measure(bgCtx, bc, origin.URL+"/large")
									if bgCtx.Err() != nil {
										return
									}
									if m.Error != "" || m.SHA256 != largeHash {
										t.Errorf("background bulk: %+v", m)
										return
									}
								}
							})
						}
						jobs := make(chan int)
						samples := make(chan measurement)
						var workers sync.WaitGroup
						for w := 0; w < perfInt("S5_PERF_CONCURRENCY", 1); w++ {
							workers.Go(func() {
								for range jobs {
									samples <- one()
								}
							})
						}
						go func() {
							for i := 0; i < count; i++ {
								jobs <- i
							}
							close(jobs)
							workers.Wait()
							close(samples)
						}()
						for m := range samples {
							if m.Error != "" || m.Status != 200 || m.SHA256 != expected || m.Bytes != int64(len(want)) {
								t.Errorf("%s: invalid response: %+v", scenario, m)
							}
							if (h2 && m.Protocol != "HTTP/2.0") || (!h2 && m.Protocol != "HTTP/1.1") {
								t.Errorf("protocol %s", m.Protocol)
							}
							if e := enc.Encode(struct {
								Mode, Scenario, Protocol, Reuse string
								Measurement                     measurement
							}{mode, scenario, protocol, reuseMode, m}); e != nil {
								t.Error(e)
							}
						}
						stopBG()
						bg.Wait()
						afterS, afterC := processUsage(t, server), processUsage(t, client)
						afterG := pidUsage(t, os.Getpid())
						if e := ue.Encode(struct {
							Mode, Scenario, Protocol, Reuse                      string
							Count                                                int
							Seconds                                              float64
							ServerBefore, ServerAfter, ClientBefore, ClientAfter perfUsage
							GeneratorBefore, GeneratorAfter                      perfUsage
						}{mode, scenario, protocol, reuseMode, count, time.Since(start).Seconds(), beforeS, afterS, beforeC, afterC, beforeG, afterG}); e != nil {
							t.Error(e)
						}
						tr.CloseIdleConnections()
					}
				}
			}
		})
	}
}
