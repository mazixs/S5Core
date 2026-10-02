// smoke starts the real s5core and s5client binaries, the ones scripts/pre-commit.sh
// built with the release flags, and sends traffic through the pair: a download
// and an upload over SOCKS5 CONNECT, and datagrams over UDP ASSOCIATE that must
// switch to the native path. Unit tests drive the code in-process; this catches
// what only the linked binary shows - a flag or an environment variable that no
// longer parses, a build without the stamped version, a log line at WARN on the
// happy path, a process that does not stop on SIGTERM.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	psk          = "smoke-psk-0123456789-abcdefghijk"
	user         = "smoke"
	password     = "smoke-password-not-a-secret"
	bodySize     = 4 << 20
	uploadSize   = 1 << 20
	stopTimeout  = 15 * time.Second
	readyTimeout = 10 * time.Second
	// Everything the run may take, a hung process included.
	overallTimeout = 3 * time.Minute
	nativeWait     = 15 * time.Second
)

func main() {
	core := flag.String("core", "", "path to the s5core binary")
	client := flag.String("client", "", "path to the s5client binary")
	version := flag.String("version", "", "version stamped into both binaries")
	flag.Parse()
	if *core == "" || *client == "" || *version == "" {
		fmt.Fprintln(os.Stderr, "usage: smoke -core PATH -client PATH -version VERSION")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	err := run(ctx, *core, *client, *version)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "smoke:", err)
		os.Exit(1)
	}
	fmt.Println("smoke: ok")
}

func run(ctx context.Context, corePath, clientPath, version string) error {
	ports, err := freePorts(4)
	if err != nil {
		return err
	}
	plain, obfs, metrics, local := ports[0], ports[1], ports[2], ports[3]

	srv := &proc{name: "s5core", path: corePath, env: []string{
		"PROXY_PORT=" + plain,
		"PROXY_LISTEN_IP=127.0.0.1",
		"PROXY_USER=" + user,
		"PROXY_PASSWORD=" + password,
		"ALLOW_PRIVATE_DEST=true",
		"OBFS_ENABLED=true",
		"OBFS_PORT=" + obfs,
		"UDP_PORT=" + obfs,
		"OBFS_PSK=" + psk,
		"METRICS_PORT=" + metrics,
		"METRICS_BIND_ADDR=127.0.0.1",
	}}
	cli := &proc{name: "s5client", path: clientPath, env: []string{
		"CLIENT_LISTEN_ADDR=127.0.0.1:" + local,
		"SERVER_ADDR=127.0.0.1:" + obfs,
		"PROXY_USER=" + user,
		"PROXY_PASS=" + password,
		"OBFS_PSK=" + psk,
		"UDP_NATIVE=true",
		"LOG_LEVEL=info",
	}}
	defer srv.kill()
	defer cli.kill()

	if err := srv.start(ctx); err != nil {
		return err
	}
	metricsURL := "http://127.0.0.1:" + metrics + "/metrics"
	if err := waitFor(readyTimeout, func() bool { _, err := scrape(ctx, metricsURL); return err == nil }); err != nil {
		return fmt.Errorf("s5core metrics did not come up: %w\n%s", err, srv.output())
	}
	if err := waitFor(readyTimeout, func() bool { return srv.logged("Obfuscation ENABLED") }); err != nil {
		return fmt.Errorf("s5core did not start the obfs listener: %w\n%s", err, srv.output())
	}
	if err := cli.start(ctx); err != nil {
		return err
	}
	localAddr := "127.0.0.1:" + local
	if err := waitFor(readyTimeout, func() bool { return dialOK(ctx, localAddr) }); err != nil {
		return fmt.Errorf("s5client did not listen: %w\n%s", err, cli.output())
	}

	withLogs := func(err error) error {
		return fmt.Errorf("%w\n%s\n%s", err, srv.output(), cli.output())
	}
	if err := checkVersion(ctx, metricsURL, version); err != nil {
		return err
	}
	target, err := startTarget()
	if err != nil {
		return err
	}
	defer target.close()

	if err := target.exchange(ctx, localAddr); err != nil {
		return withLogs(fmt.Errorf("tcp: %w", err))
	}
	if err := udpThroughTunnel(ctx, localAddr, target.udp, metricsURL); err != nil {
		return withLogs(fmt.Errorf("udp: %w", err))
	}
	if err := checkCounters(ctx, metricsURL, version); err != nil {
		return withLogs(err)
	}

	for _, p := range []*proc{cli, srv} {
		if err := p.stop(); err != nil {
			return err
		}
		if err := p.checkLog(); err != nil {
			return err
		}
	}
	return nil
}

type proc struct {
	name string
	path string
	env  []string

	cmd  *exec.Cmd
	mu   sync.Mutex
	logs bytes.Buffer
	done chan error
}

func (p *proc) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.Write(b)
}

func (p *proc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return "--- " + p.name + " ---\n" + p.logs.String()
}

func (p *proc) logged(text string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Contains(p.logs.String(), text)
}

func (p *proc) start(ctx context.Context) error {
	p.cmd = exec.CommandContext(ctx, p.path)
	p.cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}, p.env...)
	p.cmd.Stdout, p.cmd.Stderr = p, p
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", p.name, err)
	}
	p.done = make(chan error, 1)
	go func() { p.done <- p.cmd.Wait() }()
	return nil
}

func (p *proc) kill() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(stopTimeout):
	}
}

func (p *proc) stop() error {
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("%s: %w\n%s", p.name, err, p.output())
	}
	select {
	case err := <-p.done:
		p.done <- err
		if err != nil {
			return fmt.Errorf("%s did not exit cleanly on SIGTERM: %w\n%s", p.name, err, p.output())
		}
		return nil
	case <-time.After(stopTimeout):
		return fmt.Errorf("%s did not stop within %s of SIGTERM\n%s", p.name, stopTimeout, p.output())
	}
}

// checkLog fails on any line the happy path has no business writing: a WARN or
// ERROR, or a line that is not JSON at all (a panic trace, a stray fmt.Print).
func (p *proc) checkLog() error {
	p.mu.Lock()
	text := p.logs.String()
	p.mu.Unlock()
	var bad []string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		var rec struct {
			Level string `json:"level"`
			Msg   string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			bad = append(bad, "not JSON: "+line)
			continue
		}
		// net.core.rmem_max belongs to the host, not to the build under test.
		if strings.HasPrefix(rec.Msg, "UDP receive buffer") {
			continue
		}
		if strings.HasPrefix(rec.Level, "WARN") || strings.HasPrefix(rec.Level, "ERROR") {
			bad = append(bad, line)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s log: %w", p.name, err)
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s logged %d line(s) a clean run must not:\n%s", p.name, len(bad), strings.Join(bad, "\n"))
	}
	return nil
}

// freePorts returns n ports free for both TCP and UDP: the server shares one
// number between its obfs listener and its native UDP socket.
func freePorts(n int) ([]string, error) {
	var held []io.Closer
	var out []string
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for len(out) < n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		held = append(held, l)
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			continue
		}
		held = append(held, u)
		out = append(out, strconv.Itoa(port))
	}
	return out, nil
}

func waitFor(timeout time.Duration, ok func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ok() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("timeout")
}

func dialOK(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

type samples map[string]float64

// scrape reads the Prometheus text format into "name{labels}" -> value; the
// keys keep the labels exactly as exposed, so a caller matches on fragments.
func scrape(ctx context.Context, url string) (samples, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics: %s", resp.Status)
	}
	out := samples{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		out[line[:i]] += v
	}
	return out, sc.Err()
}

// sum adds every sample whose name is metric and whose labels contain all of
// the fragments.
func (s samples) sum(metric string, fragments ...string) float64 {
	var total float64
	for key, v := range s {
		if key != metric && !strings.HasPrefix(key, metric+"{") {
			continue
		}
		match := true
		for _, f := range fragments {
			if !strings.Contains(key, f) {
				match = false
				break
			}
		}
		if match {
			total += v
		}
	}
	return total
}

func (s samples) nonzero(metric string) []string {
	var out []string
	for key, v := range s {
		if (key == metric || strings.HasPrefix(key, metric+"{")) && v != 0 {
			out = append(out, fmt.Sprintf("%s %v", key, v))
		}
	}
	slices.Sort(out)
	return out
}

func checkVersion(ctx context.Context, url, version string) error {
	s, err := scrape(ctx, url)
	if err != nil {
		return err
	}
	if s.sum("s5core_build_info", `version="`+version+`"`) != 1 {
		return fmt.Errorf("s5core_build_info does not carry version %q: the binary was built without the stamp", version)
	}
	return nil
}

func checkCounters(ctx context.Context, url, version string) error {
	var s samples
	err := waitFor(5*time.Second, func() bool {
		var err error
		s, err = scrape(ctx, url)
		return err == nil && s.sum("s5core_connections_ended_total", `kind="connect"`, `result="ok"`) >= 2
	})
	if err != nil {
		return fmt.Errorf("fewer than 2 connect connections ended ok: %v", s.sum("s5core_connections_ended_total", `kind="connect"`))
	}
	if n := s.sum("s5core_client_connections_total", `client_version="`+version+`"`, `transport="obfs"`); n < 1 {
		return fmt.Errorf("s5core_client_connections_total does not count the client build %q", version)
	}
	// eof_before_frame is the ordinary-disconnect bucket (pkg/obfs/failure.go):
	// the association above ends by the application closing its socket.
	if n := s.sum("s5core_obfs_handshake_failures_total") - s.sum("s5core_obfs_handshake_failures_total", `reason="eof_before_frame"`); n != 0 {
		return fmt.Errorf("s5core_obfs_handshake_failures_total = %v besides eof_before_frame: %v", n, s.nonzero("s5core_obfs_handshake_failures_total"))
	}
	for _, bad := range []string{
		"s5core_auth_failures_total",
		"s5core_connections_rejected_total",
		"s5core_half_close_failures_total",
		"s5core_native_udp_stream_drops_total",
	} {
		if n := s.sum(bad); n != 0 {
			return fmt.Errorf("%s = %v on a clean run: %v", bad, n, s.nonzero(bad))
		}
	}
	return nil
}

type target struct {
	tcp    net.Listener
	udp    *net.UDPConn
	srv    *http.Server
	body   []byte
	digest [sha256.Size]byte
	done   chan struct{}
}

func startTarget() (*target, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	t := &target{tcp: l, udp: u, body: make([]byte, bodySize), done: make(chan struct{})}
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range t.body {
		t.body[i] = byte(rng.Uint32())
	}
	t.digest = sha256.Sum256(t.body)

	mux := http.NewServeMux()
	mux.HandleFunc("/download", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(t.body)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, _ := io.Copy(h, r.Body)
		_, _ = fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
	})
	t.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = t.srv.Serve(l) }()
	go func() {
		defer close(t.done)
		buf := make([]byte, 64<<10)
		for {
			n, addr, err := u.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = u.WriteToUDP(buf[:n], addr)
		}
	}()
	return t, nil
}

func (t *target) close() {
	_ = t.srv.Close()
	_ = t.udp.Close()
	<-t.done
}

func (t *target) exchange(ctx context.Context, proxy string) error {
	addr := t.tcp.Addr().String()
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", proxy)
			if err != nil {
				return nil, err
			}
			if err := connect(c, t.tcp.Addr().(*net.TCPAddr)); err != nil {
				_ = c.Close()
				return nil, err
			}
			return c, nil
		},
	}
	defer tr.CloseIdleConnections()
	hc := http.Client{Transport: tr, Timeout: 30 * time.Second}

	get, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/download", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(get)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if n != bodySize || [sha256.Size]byte(h.Sum(nil)) != t.digest {
		return fmt.Errorf("download: got %d bytes with a different digest", n)
	}

	up := make([]byte, uploadSize)
	rng := rand.New(rand.NewPCG(3, 4))
	for i := range up {
		up[i] = byte(rng.Uint32())
	}
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+"/upload", bytes.NewReader(up))
	if err != nil {
		return err
	}
	resp, err = hc.Do(post)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	reply, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	want := fmt.Sprintf("%d %x", uploadSize, sha256.Sum256(up))
	if string(reply) != want {
		return fmt.Errorf("upload: server saw %q, want %q", reply, want)
	}
	return nil
}

func greet(c net.Conn) error {
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return err
	}
	if r != [2]byte{5, 0} {
		return fmt.Errorf("greeting answered %v", r)
	}
	return nil
}

// request sends a SOCKS5 request for the IPv4 address and returns the bound
// address from the reply.
func request(c net.Conn, cmd byte, to *net.UDPAddr) (*net.UDPAddr, error) {
	req := []byte{5, cmd, 0, 1}
	req = append(req, to.IP.To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(to.Port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	var r [10]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return nil, err
	}
	if r[0] != 5 || r[1] != 0 || r[3] != 1 {
		return nil, fmt.Errorf("request %#x answered %v", cmd, r)
	}
	return &net.UDPAddr{IP: net.IP(r[4:8]), Port: int(binary.BigEndian.Uint16(r[8:10]))}, nil
}

func connect(c net.Conn, to *net.TCPAddr) error {
	if err := greet(c); err != nil {
		return err
	}
	_, err := request(c, 1, &net.UDPAddr{IP: to.IP, Port: to.Port})
	return err
}

// udpThroughTunnel echoes datagrams of several sizes through the association
// until the server has counted native datagrams both ways, then requires a
// final burst to come back whole.
func udpThroughTunnel(ctx context.Context, proxy string, echo *net.UDPConn, metricsURL string) error {
	d := net.Dialer{Timeout: 2 * time.Second}
	ctl, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return err
	}
	defer func() { _ = ctl.Close() }()
	_ = ctl.SetDeadline(time.Now().Add(readyTimeout + nativeWait + 15*time.Second))
	if err := greet(ctl); err != nil {
		return err
	}
	relay, err := request(ctl, 3, &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return err
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer func() { _ = app.Close() }()

	dst := echo.LocalAddr().(*net.UDPAddr)
	header := append([]byte{0, 0, 0, 1}, dst.IP.To4()...)
	header = binary.BigEndian.AppendUint16(header, uint16(dst.Port))
	sizes := []int{16, 200, 1000}
	seq := uint32(0)

	roundTrip := func(size int) error {
		payload := make([]byte, size)
		binary.BigEndian.PutUint32(payload, seq)
		seq++
		if _, err := app.WriteToUDP(append(append([]byte(nil), header...), payload...), relay); err != nil {
			return err
		}
		buf := make([]byte, 2048)
		_ = app.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := app.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("datagram %d of %d bytes got no echo: %w", seq-1, size, err)
		}
		if n < len(header) || !bytes.Equal(buf[len(header):n], payload) {
			return fmt.Errorf("datagram %d came back changed", seq-1)
		}
		return nil
	}

	native := func() (bool, error) {
		s, err := scrape(ctx, metricsURL)
		if err != nil {
			return false, err
		}
		return s.sum("s5core_native_udp_datagrams_total", `direction="from_client"`, `path="native"`) > 0 &&
			s.sum("s5core_native_udp_datagrams_total", `direction="to_client"`, `path="native"`) > 0, nil
	}

	deadline := time.Now().Add(nativeWait)
	for {
		for _, size := range sizes {
			if err := roundTrip(size); err != nil {
				return err
			}
		}
		ok, err := native()
		if err != nil {
			return err
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no native datagrams in %s: the association stayed on the TCP tunnel", nativeWait)
		}
		time.Sleep(100 * time.Millisecond)
	}

	for range 30 {
		for _, size := range sizes {
			if err := roundTrip(size); err != nil {
				return err
			}
		}
	}
	return nil
}
