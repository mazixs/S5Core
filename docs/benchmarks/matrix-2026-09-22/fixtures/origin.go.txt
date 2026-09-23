package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const largeSize = 8 << 20

var (
	smallBody = []byte("s5core-matrix-small-body")
	largeBody = bytes.Repeat([]byte("0123456789abcdef"), largeSize/16)
)

type origin struct {
	HTTP    string `json:"http"`
	HTTPS   string `json:"https"`
	H3      string `json:"h3"`
	TCPEcho string `json:"tcp_echo"`
	UDPEcho string `json:"udp_echo"`
	CertPEM string `json:"cert_pem"`
	roots   *x509.CertPool
}

// allowed admits loopback and the listed sources; a public origin must not
// serve anyone else.
type allowed []netip.Prefix

func (a allowed) ok(addr net.Addr) bool {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	if ip.IsLoopback() {
		return true
	}
	for _, p := range a {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type filteredListener struct {
	net.Listener
	allow allowed
}

func (l filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || l.allow.ok(c.RemoteAddr()) {
			return c, err
		}
		_ = c.Close()
	}
}

type filteredPacketConn struct {
	*net.UDPConn
	allow allowed
}

func (c filteredPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.UDPConn.ReadFrom(b)
		if err != nil || c.allow.ok(a) {
			return n, a, err
		}
	}
}

func selfSigned(ip net.IP) (tls.Certificate, *x509.CertPool, string) {
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
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func loadOrigin(path string) *origin {
	b, err := os.ReadFile(path)
	must(err)
	o := &origin{}
	must(json.Unmarshal(b, o))
	o.roots = x509.NewCertPool()
	if !o.roots.AppendCertsFromPEM([]byte(o.CertPEM)) {
		panic("origin file has no certificate")
	}
	return o
}

func mux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/small", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(smallBody) })
	m.HandleFunc("/proto", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.Proto)) })
	m.HandleFunc("/large", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(largeBody)))
		_, _ = w.Write(largeBody)
	})
	m.HandleFunc("/size", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		n = min(max(n, 0), len(largeBody))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = w.Write(largeBody[:n])
	})
	m.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(strconv.FormatInt(n, 10)))
	})
	return m
}

func startOrigin(ip net.IP, allow allowed) *origin {
	cert, pool, certPEM := selfSigned(ip)
	o := &origin{roots: pool, CertPEM: certPEM}
	tcp := func() net.Listener {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: ip})
		must(err)
		return filteredListener{l, allow}
	}
	udp := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
		must(err)
		_ = c.SetReadBuffer(8 << 20)
		_ = c.SetWriteBuffer(8 << 20)
		return c
	}

	hl := tcp()
	o.HTTP = hl.Addr().String()
	go func() { _ = (&http.Server{Handler: mux(), ReadHeaderTimeout: 10 * time.Second}).Serve(hl) }()

	sl := tcp()
	o.HTTPS = sl.Addr().String()
	go func() {
		srv := &http.Server{Handler: mux(), ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		_ = srv.ServeTLS(sl, "", "")
	}()

	pc := udp()
	o.H3 = pc.LocalAddr().String()
	h3 := &http3.Server{Handler: mux(), TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})}
	go func() { _ = h3.Serve(filteredPacketConn{pc, allow}) }()

	tl := tcp()
	o.TCPEcho = tl.Addr().String()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	ue := udp()
	o.UDPEcho = ue.LocalAddr().String()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := ue.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			if allow.ok(net.UDPAddrFromAddrPort(a)) {
				_, _ = ue.WriteToUDPAddrPort(b[:n], a)
			}
		}
	}()
	return o
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
