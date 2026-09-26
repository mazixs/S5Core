package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

type countKey struct {
	run  uint32
	size int
}

type count struct {
	Up    int `json:"up"`
	UpBad int `json:"up_bad,omitempty"`
	Asked int `json:"asked"`
}

type echoState struct {
	mu     sync.Mutex
	counts map[countKey]*count
}

func (e *echoState) at(run uint32, size int) *count {
	k := countKey{run, size}
	c := e.counts[k]
	if c == nil {
		c = &count{}
		e.counts[k] = c
	}
	return c
}

func runEcho(args []string) {
	fs := flag.NewFlagSet("echo", flag.ExitOnError)
	udpAddr := fs.String("udp", "", "UDP address of the echo")
	httpAddr := fs.String("http", "", "HTTP address of the bulk origin")
	h3Addr := fs.String("h3", "", "UDP address of the HTTP/3 origin, on a bare socket")
	mgmt := fs.String("mgmt", "", "HTTP address that reports the counts")
	initial := fs.Uint("initial", 0, "InitialPacketSize of the HTTP/3 origin; 0 keeps the quic-go default")
	pmtud := fs.Bool("pmtud", true, "path MTU discovery of the HTTP/3 origin")
	must(fs.Parse(args))

	st := &echoState{counts: map[countKey]*count{}}
	if *udpAddr != "" {
		ua, err := net.ResolveUDPAddr("udp", *udpAddr)
		must(err)
		c, err := net.ListenUDP("udp", ua)
		must(err)
		_ = c.SetReadBuffer(8 << 20)
		_ = c.SetWriteBuffer(8 << 20)
		go st.serveUDP(c)
	}
	var mtu mtuLog
	if *httpAddr != "" {
		l, err := net.Listen("tcp", *httpAddr)
		must(err)
		go func() { _ = (&http.Server{Handler: bulkMux(), ReadHeaderTimeout: 10 * time.Second}).Serve(l) }()
	}
	if *h3Addr != "" {
		ua, err := net.ResolveUDPAddr("udp", *h3Addr)
		must(err)
		pc, err := net.ListenUDP("udp", ua)
		must(err)
		srv := &http3.Server{Handler: bulkMux(),
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{selfSigned(ua.IP)}, MinVersion: tls.VersionTLS13}),
			QUICConfig: &quic.Config{MaxIdleTimeout: 60 * time.Second, InitialPacketSize: uint16(*initial),
				DisablePathMTUDiscovery: !*pmtud, Tracer: mtu.tracer("server")}}
		go func() { _ = srv.Serve(pc) }()
	}
	m := http.NewServeMux()
	m.HandleFunc("/count", func(w http.ResponseWriter, r *http.Request) {
		run, _ := strconv.ParseUint(r.URL.Query().Get("run"), 10, 32)
		out := map[string]count{}
		st.mu.Lock()
		for k, c := range st.counts {
			if k.run == uint32(run) {
				out[strconv.Itoa(k.size)] = *c
			}
		}
		st.mu.Unlock()
		writeTo(w, out)
	})
	m.HandleFunc("/mtu", func(w http.ResponseWriter, r *http.Request) { writeTo(w, mtu.take()) })
	must(http.ListenAndServe(*mgmt, m))
}

func (e *echoState) serveUDP(c *net.UDPConn) {
	b := make([]byte, 65535)
	back := make([]byte, 65535)
	for {
		n, a, err := c.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		kind, run, size, seq, ok := header(b[:n])
		if !ok {
			continue
		}
		e.mu.Lock()
		switch kind {
		case kindUp:
			if n == size {
				e.at(run, size).Up++
			} else {
				e.at(run, size).UpBad++
			}
		case kindAsk:
			e.at(run, size).Asked++
		}
		e.mu.Unlock()
		if kind == kindAsk && size >= hdrLen && size <= len(back) {
			putHeader(back, kindBack, run, size, seq)
			_, _ = c.WriteToUDPAddrPort(back[:size], a)
		}
	}
}

func writeTo(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	_, _ = w.Write(b)
}

// bulkMux serves /bytes?n=N and takes /sink uploads, for TCP and HTTP/3.
func bulkMux() *http.ServeMux {
	m := http.NewServeMux()
	chunk := make([]byte, 64<<10)
	_, _ = rand.Read(chunk)
	m.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		for n > 0 {
			k := min(n, int64(len(chunk)))
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	m.HandleFunc("/sink", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(strconv.FormatInt(n, 10)))
	})
	return m
}

func selfSigned(ip net.IP) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: ip.String()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{ip, net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// mtuLog keeps the MTU updates of quic-go's path MTU discovery, by side.
type mtuLog struct {
	mu     sync.Mutex
	start  time.Time
	events []mtuEvent
}

type mtuEvent struct {
	Side string  `json:"side"`
	Conn int     `json:"conn"`
	AtMs float64 `json:"at_ms"`
	MTU  int     `json:"mtu"`
	Done bool    `json:"done"`
	Lost int     `json:"lost_so_far"`
}

func (l *mtuLog) take() []mtuEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]mtuEvent(nil), l.events...)
}

func (l *mtuLog) tracer(side string) func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
	var conns int
	return func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		l.mu.Lock()
		conns++
		if l.start.IsZero() {
			l.start = time.Now()
		}
		l.mu.Unlock()
		return &mtuTrace{log: l, side: side, conn: conns}
	}
}

type mtuTrace struct {
	log  *mtuLog
	side string
	conn int
	lost int
}

func (t *mtuTrace) AddProducer() qlogwriter.Recorder { return t }
func (t *mtuTrace) SupportsSchemas(string) bool      { return true }
func (t *mtuTrace) Close() error                     { return nil }

func (t *mtuTrace) RecordEvent(e qlogwriter.Event) {
	t.log.mu.Lock()
	defer t.log.mu.Unlock()
	switch e := e.(type) {
	case qlog.PacketLost:
		t.lost++
	case qlog.MTUUpdated:
		t.log.events = append(t.log.events, mtuEvent{Side: t.side, Conn: t.conn,
			AtMs: float64(time.Since(t.log.start).Microseconds()) / 1000, MTU: e.Value, Done: e.Done, Lost: t.lost})
	}
}
