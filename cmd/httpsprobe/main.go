// httpsprobe measures HTTP response timing at the client, outside the proxy.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

type measurement struct {
	StartedNS       int64   `json:"started_unix_ns"`
	Protocol        string  `json:"protocol,omitempty"`
	Status          int     `json:"status,omitempty"`
	Reused          bool    `json:"reused"`
	DNSMS           float64 `json:"client_dns_ms"`
	SetupMS         float64 `json:"connect_setup_ms"`
	TLSMS           float64 `json:"tls_handshake_ms"`
	FirstResponseMS float64 `json:"http_first_response_ms"`
	TotalMS         float64 `json:"total_ms"`
	Bytes           int64   `json:"bytes"`
	SHA256          string  `json:"sha256,omitempty"`
	Error           string  `json:"error,omitempty"`
}

// Setup measures DialContext in full: direct DNS/TCP, or TCP to the proxy
// plus SOCKS greeting and CONNECT. Remote DNS cannot be separated at this
// endpoint; the server's dns phase supplies that observation.
type probeTransport struct{ *http.Transport }

func newTransport(socks string, roots *x509.CertPool, reuse, http2 bool, budget time.Duration) (*probeTransport, error) {
	dial := (&net.Dialer{}).DialContext
	if socks != "" {
		d, err := proxy.SOCKS5("tcp", socks, nil, &net.Dialer{})
		if err != nil {
			return nil, err
		}
		dial = d.(proxy.ContextDialer).DialContext
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, ForceAttemptHTTP2: http2, DisableKeepAlives: !reuse, DisableCompression: true}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		start := time.Now()
		c, err := dial(ctx, network, addr)
		if record, ok := ctx.Value(timingKey{}).(*timing); ok {
			record.mu.Lock()
			record.result.SetupMS = milliseconds(time.Since(start))
			record.mu.Unlock()
		}
		return c, err
	}
	return &probeTransport{tr}, nil
}

type timingKey struct{}
type timing struct {
	mu     sync.Mutex
	result measurement
}

// Keep the load generator's buffer churn out of proxy latency measurements.
// Each active response owns its buffer until the complete body is consumed.
var responseBuffers = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func measure(ctx context.Context, client *http.Client, target string) measurement {
	return measureBody(ctx, client, target, http.MethodGet, nil)
}

func measureBody(ctx context.Context, client *http.Client, target, method string, body io.Reader) measurement {
	start := time.Now()
	record := new(timing)
	var tlsStart, dnsStart time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { record.mu.Lock(); dnsStart = time.Now(); record.mu.Unlock() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			record.mu.Lock()
			record.result.DNSMS += milliseconds(time.Since(dnsStart))
			record.mu.Unlock()
		},
		TLSHandshakeStart: func() { record.mu.Lock(); tlsStart = time.Now(); record.mu.Unlock() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			record.mu.Lock()
			record.result.TLSMS += milliseconds(time.Since(tlsStart))
			record.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			record.mu.Lock()
			record.result.Reused = info.Reused
			record.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			record.mu.Lock()
			record.result.FirstResponseMS = milliseconds(time.Since(start))
			record.mu.Unlock()
		},
	}
	ctx = context.WithValue(ctx, timingKey{}, record)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, target, body)
	var resp *http.Response
	if err == nil {
		resp, err = client.Do(req)
	}
	var n int64
	var checksum string
	if resp != nil {
		hash := sha256.New()
		buffer := responseBuffers.Get().(*[32 * 1024]byte)
		n, err = io.CopyBuffer(hash, resp.Body, buffer[:])
		responseBuffers.Put(buffer)
		closeErr := resp.Body.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			checksum = hex.EncodeToString(hash.Sum(nil))
		}
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	result := record.result
	result.StartedNS = start.UnixNano()
	result.TotalMS = milliseconds(time.Since(start))
	result.Bytes = n
	result.SHA256 = checksum
	if resp != nil {
		result.Protocol = resp.Proto
		result.Status = resp.StatusCode
	}
	if err != nil {
		// url.Error includes the full URL, possibly with credentials or tokens.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		result.Error = err.Error()
	}
	return result
}

func run(args []string, output, stderr io.Writer) error {
	flags := flag.NewFlagSet("httpsprobe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("url", "", "HTTPS URL to measure")
	socks := flags.String("socks", "", "SOCKS5 host:port; empty uses a direct connection")
	timeout := flags.Duration("timeout", 30*time.Second, "total budget per request, including body")
	count := flags.Int("count", 1, "number of sequential requests")
	reuse := flags.Bool("reuse", false, "reuse HTTP connections")
	http2 := flags.Bool("http2", true, "allow HTTP/2; negotiated protocol is reported")
	ca := flags.String("ca", "", "PEM CA file to add to system roots")
	if err := flags.Parse(args); err != nil {
		return err
	}
	u, err := url.Parse(*target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("provide an HTTPS -url without user info")
	}
	if *count < 1 || *timeout <= 0 {
		return errors.New("count and timeout must be positive")
	}
	var roots *x509.CertPool
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("CA file contains no certificates")
		}
	}
	tr, err := newTransport(*socks, roots, *reuse, *http2, *timeout)
	if err != nil {
		return err
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: *timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	encoder := json.NewEncoder(output)
	failed := false
	for i := 0; i < *count; i++ {
		result := measure(context.Background(), client, *target)
		if err := encoder.Encode(result); err != nil {
			return err
		}
		failed = failed || result.Error != "" || result.Status < 200 || result.Status >= 300
	}
	if failed {
		return errors.New("one or more requests failed; see JSON measurements")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
