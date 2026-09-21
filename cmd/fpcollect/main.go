// Command fpcollect is the receiving half of level 4 of the stealth
// checklist: it answers the question "what does a server write down about
// this client" with the bytes the client actually sent.
//
// Levels 1-3 measure whether a censor blocks the first packet. They say
// nothing about the case where the packet is allowed through and recorded -
// and a TLS client announces its cipher list, extension list and their order
// in the clear, which is stable per implementation and is what JA3 and JA4
// hash. TLS_FINGERPRINT exists so the WSS transport does not stand out there.
// internal/stealth tests that claim offline; this collector tests it on the
// path, where the answer can differ: a middlebox that terminates TLS, a CDN
// in front of the node or a client built with a different uTLS version all
// change what arrives without changing anything in the repository.
//
// It is deliberately its own service and not an endpoint of s5core. A server
// that reports fingerprints back to whoever asks is a reconnaissance tool
// pointed at itself, and the production binary has no business offering one.
//
//	fpcollect -addr :8443                     самоподписанный сертификат
//	fpcollect -addr :8443 -cert c.pem -key k.pem
//	curl -sk https://node:8443/ | jq
//
// The port is opened for the duration of a measurement and closed after, the
// same way the bandwidth stand in docs/field/nodes.md opens one.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mazixs/S5Core/internal/stealth"
)

func main() {
	addr := flag.String("addr", ":8443", "адрес прослушивания")
	certFile := flag.String("cert", "", "сертификат PEM (пусто - самоподписанный на лету)")
	keyFile := flag.String("key", "", "ключ PEM")
	name := flag.String("name", "localhost", "имя в самоподписанном сертификате")
	alpn := flag.String("alpn", "http/1.1", "протоколы ALPN через запятую, которые сервер готов выбрать; пусто - не выбирать ни одного")
	quiet := flag.Bool("quiet", false, "не печатать строку на каждое соединение")
	flag.Parse()

	cert, err := loadOrCreateCert(*certFile, *keyFile, *name)
	if err != nil {
		log.Fatalf("сертификат: %v", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if *alpn != "" {
		cfg.NextProtos = strings.Split(*alpn, ",")
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("слушаю %s: %v", *addr, err)
	}
	defer func() { _ = ln.Close() }()
	log.Printf("fpcollect слушает %s, ALPN %q", ln.Addr(), *alpn)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go serve(conn, cfg, *quiet)
	}
}

// report is what the collector sends back. Everything in it is derived from
// this one connection: the collector never reports on anyone else, which is
// what makes it safe to leave running while a measurement is in progress.
type report struct {
	IP   string `json:"ip"`
	Port string `json:"port"`

	JA3       string `json:"ja3"`
	JA3String string `json:"ja3_string"`
	JA4       string `json:"ja4"`

	SNI             string   `json:"sni"`
	ALPNOffered     []string `json:"alpn_offered"`
	ALPNNegotiated  string   `json:"alpn_negotiated"`
	GREASE          bool     `json:"grease"`
	CipherCount     int      `json:"cipher_count"`
	ExtensionCount  int      `json:"extension_count"`
	HelloBytes      int      `json:"hello_bytes"`
	VersionOffered  string   `json:"tls_version_offered"`
	VersionAccepted string   `json:"tls_version_negotiated"`
	CipherAccepted  string   `json:"cipher_negotiated"`

	// HandshakeRTTMs is the path's round trip as the local stack measured it,
	// not as the application timed it. A timing taken around Handshake()
	// includes whatever the peer was doing; this does not.
	HandshakeRTTMs float64 `json:"handshake_rtt_ms,omitempty"`
	MSS            uint32  `json:"mss,omitempty"`

	// Note carries the one reading a fingerprint cannot give by itself.
	Note string `json:"note,omitempty"`
}

func serve(raw net.Conn, cfg *tls.Config, quiet bool) {
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))

	hello, prefix, err := readClientHello(raw)
	if err != nil {
		if !quiet {
			log.Printf("%s: %v", raw.RemoteAddr(), err)
		}
		return
	}

	rep := report{HelloBytes: len(prefix)}
	host, port, _ := net.SplitHostPort(raw.RemoteAddr().String())
	rep.IP, rep.Port = host, port
	rep.JA3, rep.JA3String, rep.JA4 = hello.JA3(), hello.JA3String(), hello.JA4()
	rep.SNI, rep.ALPNOffered, rep.GREASE = hello.ServerName, hello.ALPN, hello.HadGREASE
	rep.CipherCount, rep.ExtensionCount = len(hello.CipherSuites), len(hello.Extensions)
	rep.VersionOffered = versionName(highestVersion(hello))

	if rtt, mss, err := pathInfo(raw); err == nil {
		rep.HandshakeRTTMs, rep.MSS = float64(rtt)/1000.0, mss
	}

	// The hello has been consumed off the socket, so the TLS server is given
	// it back before anything else it reads.
	tlsConn := tls.Server(&replayConn{Conn: raw, pre: prefix}, cfg)
	hsCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		if !quiet {
			log.Printf("%s ja4=%s: рукопожатие не состоялось: %v", rep.IP, rep.JA4, err)
		}
		return
	}
	state := tlsConn.ConnectionState()
	rep.VersionAccepted = versionName(state.Version)
	rep.CipherAccepted = tls.CipherSuiteName(state.CipherSuite)
	rep.ALPNNegotiated = state.NegotiatedProtocol
	if len(rep.ALPNOffered) > 0 && rep.ALPNNegotiated == "" {
		rep.Note = "клиент предложил ALPN, сервер не выбрал ни одного - обычный сайт так не отвечает"
	}

	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return
	}
	body = append(body, '\n')

	// Read and discard the request line: without it a client using keep-alive
	// sees the response before it has finished sending, and curl reports a
	// broken pipe instead of the body.
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	_, _ = tlsConn.Read(buf)

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	_ = tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := tlsConn.Write(append([]byte(resp), body...)); err != nil {
		return
	}
	_ = tlsConn.Close()

	if !quiet {
		log.Printf("%s ja4=%s sni=%q alpn=%v->%q grease=%v", rep.IP, rep.JA4, rep.SNI, rep.ALPNOffered, rep.ALPNNegotiated, rep.GREASE)
	}
}

// readClientHello reads exactly the records that carry the ClientHello and
// returns both the parsed form and the raw bytes, which the TLS server still
// needs.
func readClientHello(c net.Conn) (*stealth.ClientHello, []byte, error) {
	var raw []byte
	for range 8 { // a hello split across more records than this is not one we need to serve
		head := make([]byte, 5)
		if _, err := io.ReadFull(c, head); err != nil {
			return nil, raw, fmt.Errorf("чтение заголовка записи: %w", err)
		}
		body := make([]byte, int(binary.BigEndian.Uint16(head[3:5])))
		if _, err := io.ReadFull(c, body); err != nil {
			return nil, raw, fmt.Errorf("чтение записи: %w", err)
		}
		raw = append(append(raw, head...), body...)
		if hello, err := stealth.ParseClientHello(raw); err == nil {
			return hello, raw, nil
		}
	}
	return nil, raw, fmt.Errorf("это не ClientHello (%d байт)", len(raw))
}

// replayConn hands back bytes already taken off the socket before reading any
// more from it.
type replayConn struct {
	net.Conn
	pre []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func highestVersion(h *stealth.ClientHello) uint16 {
	best := h.LegacyVersion
	for _, v := range h.SupportedVersions {
		if v > best {
			best = v
		}
	}
	return best
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func loadOrCreateCert(certFile, keyFile, name string) (tls.Certificate, error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return tls.Certificate{}, fmt.Errorf("нужны оба: -cert и -key")
		}
		return tls.LoadX509KeyPair(certFile, keyFile)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{name},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	fmt.Fprintln(os.Stderr, "сертификат самоподписанный и живет сутки: клиент должен ходить с -k или с этим корнем")
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
