package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// nativeMaxPayload is the longest SOCKS5 UDP datagram native carries:
// nativeudp.MaxWire (1400) less the tag, kind, pad length and AEAD tag.
const nativeMaxPayload = 1374

type packet struct {
	at   time.Duration
	up   bool
	size int
}

// forwarded records the datagrams a forwarder relayed, by direction.
type forwarded struct {
	mu    sync.Mutex
	start time.Time
	pkts  []packet
}

func (f *forwarded) add(up bool, n int) {
	f.mu.Lock()
	f.pkts = append(f.pkts, packet{time.Since(f.start), up, n})
	f.mu.Unlock()
}

type dirSummary struct {
	Packets   int         `json:"packets"`
	Bytes     int         `json:"bytes"`
	Max       int         `json:"max"`
	OverLimit int         `json:"over_native_limit"`
	Steady    int         `json:"steady_size"`
	SteadyN   int         `json:"steady_count"`
	Large     map[int]int `json:"sizes_from_1200"`
	// MaxBy250ms is the largest datagram of every 250 ms, the course of the search.
	MaxBy250ms []int `json:"max_by_250ms"`
}

func (f *forwarded) summary(from, to time.Duration, up bool, limit int) dirSummary {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := dirSummary{Large: map[int]int{}}
	mid := from + (to-from)/2
	late := map[int]int{}
	for _, p := range f.pkts {
		if p.up != up || p.at < from || p.at > to {
			continue
		}
		s.Packets++
		s.Bytes += p.size
		s.Max = max(s.Max, p.size)
		if p.size > limit {
			s.OverLimit++
		}
		if p.size >= 1200 {
			s.Large[p.size]++
			if p.at >= mid {
				late[p.size]++
			}
		}
		w := int((p.at - from) / (250 * time.Millisecond))
		for len(s.MaxBy250ms) <= w {
			s.MaxBy250ms = append(s.MaxBy250ms, 0)
		}
		s.MaxBy250ms[w] = max(s.MaxBy250ms[w], p.size)
	}
	for size, n := range late {
		if n > s.SteadyN || n == s.SteadyN && size > s.Steady {
			s.Steady, s.SteadyN = size, n
		}
	}
	return s
}

type phase struct {
	Name     string             `json:"name"`
	Bytes    int64              `json:"bytes"`
	Seconds  float64            `json:"seconds"`
	MBps     float64            `json:"mb_per_s"`
	Error    string             `json:"error,omitempty"`
	Up       *dirSummary        `json:"client_to_origin,omitempty"`
	Down     *dirSummary        `json:"origin_to_client,omitempty"`
	Metrics  map[string]float64 `json:"metrics,omitempty"`
	from, to time.Duration
}

type quicOut struct {
	Mode        string     `json:"mode"`
	Target      string     `json:"target"`
	SocksHeader int        `json:"socks_header,omitempty"`
	NativeLimit int        `json:"native_limit_payload,omitempty"`
	WarmupMs    int64      `json:"warmup_ms,omitempty"`
	Phases      []phase    `json:"phases"`
	ClientMTU   []mtuEvent `json:"client_mtu"`
	OriginMTU   []mtuEvent `json:"origin_mtu"`
}

func runQUIC(args []string) {
	fs := flag.NewFlagSet("quic", flag.ExitOnError)
	socks := fs.String("socks", "", "SOCKS5 address of s5client; empty runs QUIC directly")
	target := fs.String("target", "", "UDP address of the HTTP/3 origin")
	echo := fs.String("echo", "", "UDP address of the echo, for the warmup")
	bind := fs.String("bind", "", "local IP of the direct socket")
	mgmt := fs.String("mgmt", "", "base URL of the echo's counts")
	metrics := fs.String("metrics", "", "URL of the server metrics")
	down := fs.Int64("down", 8<<20, "bytes to download")
	up := fs.Int64("up", 4<<20, "bytes to upload")
	timeout := fs.Duration("timeout", 60*time.Second, "limit of each transfer")
	initial := fs.Uint("initial", 0, "InitialPacketSize of QUIC; 0 keeps the quic-go default (1280)")
	pmtud := fs.Bool("pmtud", true, "path MTU discovery of QUIC; false keeps -initial for the whole connection")
	out := fs.String("out", "", "JSON output")
	must(fs.Parse(args))

	ta, err := net.ResolveUDPAddr("udp", *target)
	must(err)
	res := quicOut{Mode: "direct", Target: *target}
	originBefore := len(fetchMTU(*mgmt))
	var log mtuLog
	var fw *forwarded
	dialTo := ta
	var qc *net.UDPConn
	if *socks == "" {
		qc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(*bind)})
		must(err)
	} else {
		res.Mode = "tunnel"
		head := socksHeader(ta)
		res.SocksHeader, res.NativeLimit = len(head), nativeMaxPayload-len(head)
		assoc, err := associate(*socks)
		must(err)
		defer assoc.Close()
		res.WarmupMs = warmNative(assoc, *echo, *metrics)
		fwd, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		must(err)
		_ = fwd.SetReadBuffer(8 << 20)
		_ = fwd.SetWriteBuffer(8 << 20)
		fw = &forwarded{start: time.Now()}
		var client atomic.Pointer[net.UDPAddr]
		go func() {
			b := make([]byte, 65535)
			w := make([]byte, 0, 65600)
			for {
				n, a, err := fwd.ReadFromUDP(b)
				if err != nil {
					return
				}
				client.Store(a)
				fw.add(true, n)
				_ = assoc.send(w, head, b[:n])
			}
		}()
		go func() {
			b := make([]byte, 65535)
			for {
				d, err := assoc.recv(b)
				if err != nil {
					return
				}
				if a := client.Load(); a != nil {
					fw.add(false, len(d))
					_, _ = fwd.WriteToUDP(d, a)
				}
			}
		}()
		dialTo = fwd.LocalAddr().(*net.UDPAddr)
		qc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		must(err)
	}
	// A real *net.UDPConn under quic.Transport: quic-go sets DF and searches
	// the path MTU only on such a socket.
	tr := &quic.Transport{Conn: qc}
	h3 := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		QUICConfig: &quic.Config{MaxIdleTimeout: 30 * time.Second, InitialPacketSize: uint16(*initial),
			DisablePathMTUDiscovery: !*pmtud, Tracer: log.tracer("client")},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return tr.DialEarly(ctx, dialTo, tlsCfg, cfg)
		},
	}
	defer h3.Close()
	client := &http.Client{Transport: h3, Timeout: *timeout}
	base := "https://" + *target

	run := func(name string, do func() (int64, error)) {
		p := phase{Name: name}
		m0 := scrape(*metrics)
		t0 := time.Now()
		if fw != nil {
			p.from = time.Since(fw.start)
		}
		n, err := do()
		p.Seconds = time.Since(t0).Seconds()
		p.Bytes = n
		p.MBps = float64(n) / p.Seconds / 1e6
		if err != nil {
			p.Error = err.Error()
		}
		time.Sleep(300 * time.Millisecond)
		if *metrics != "" {
			p.Metrics = metricDelta(m0, scrape(*metrics))
		}
		if fw != nil {
			p.to = time.Since(fw.start)
			u, d := fw.summary(p.from, p.to, true, res.NativeLimit), fw.summary(p.from, p.to, false, res.NativeLimit)
			p.Up, p.Down = &u, &d
		}
		res.Phases = append(res.Phases, p)
	}
	download := func() (int64, error) {
		resp, err := client.Get(base + "/bytes?n=" + strconv.FormatInt(*down, 10))
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return io.Copy(io.Discard, resp.Body)
	}
	run("download", download)
	run("upload", func() (int64, error) {
		resp, err := client.Post(base+"/sink", "application/octet-stream", io.LimitReader(zeros{}, *up))
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		n, _ := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
		if n != *up {
			return n, fmt.Errorf("origin took %d of %d bytes", n, *up)
		}
		return n, nil
	})
	// The first download overlaps the search of the origin; this one follows it.
	run("download_after", download)
	res.ClientMTU = log.take()
	if o := fetchMTU(*mgmt); len(o) > originBefore {
		res.OriginMTU = o[originBefore:]
	}
	sort.SliceStable(res.OriginMTU, func(i, j int) bool { return res.OriginMTU[i].AtMs < res.OriginMTU[j].AtMs })
	writeJSON(*out, res)
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) {
	clear(b)
	return len(b), nil
}

// warmNative sends small datagrams to the echo until the server counts
// native both ways, and reports how long it took (-1 if it never did).
func warmNative(assoc *socksUDP, echo, metrics string) int64 {
	ea, err := net.ResolveUDPAddr("udp", echo)
	must(err)
	head := socksHeader(ea)
	start := time.Now()
	m0 := scrape(metrics)
	ask := make([]byte, 32)
	w := make([]byte, 0, 128)
	for i := 0; time.Since(start) < 15*time.Second; i++ {
		putHeader(ask, kindAsk, 7, 64, uint32(i))
		_ = assoc.send(w, head, ask)
		time.Sleep(20 * time.Millisecond)
		if i%5 == 4 {
			d := metricDelta(m0, scrape(metrics))
			if metric(d, "s5core_native_udp_datagrams_total", `direction="from_client"`, `path="native"`) > 0 &&
				metric(d, "s5core_native_udp_datagrams_total", `direction="to_client"`, `path="native"`) > 0 {
				// Late answers of the warmup must not reach QUIC.
				time.Sleep(300 * time.Millisecond)
				b := make([]byte, 65535)
				_ = assoc.udp.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				for {
					if _, _, err := assoc.udp.ReadFromUDP(b); err != nil {
						break
					}
				}
				_ = assoc.udp.SetReadDeadline(time.Time{})
				return time.Since(start).Milliseconds()
			}
		}
	}
	return -1
}

func fetchMTU(base string) []mtuEvent {
	if base == "" {
		return nil
	}
	resp, err := httpc.Get(base + "/mtu")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out []mtuEvent
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}
