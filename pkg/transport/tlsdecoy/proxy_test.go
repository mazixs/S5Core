package tlsdecoy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// Plan task Ф5-6: the cover story stops being a page and becomes a site.
// What these check is the property the task asks for - that a probe asking
// for the tunnel's own path, for a path that does not exist, or for the
// front page cannot tell from the answers that any of them is special.

// upstreamSite is a small site with the traits that matter: a front page, a
// path that does not exist, a redirect to itself and a cookie scoped to its
// own domain. It records what it was asked, so a test can also check what
// the proxy did not forward.
type upstreamSite struct {
	*httptest.Server
	requests atomic.Int64
	// lastHeader is the header of the most recent request.
	lastHeader atomic.Pointer[http.Header]
	// lastHost is the Host of the most recent request, which does not
	// travel in Header.
	lastHost atomic.Pointer[string]
}

func startUpstream(t *testing.T) *upstreamSite {
	t.Helper()
	site := &upstreamSite{}
	site.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		site.requests.Add(1)
		header := r.Header.Clone()
		site.lastHeader.Store(&header)
		host := r.Host
		site.lastHost.Store(&host)

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Upstream-Marker", "front-page")
			_, _ = io.WriteString(w, "<html><body>upstream front page</body></html>")
		case "/login":
			w.Header().Set("Set-Cookie", "session=abc; Domain="+r.Host+"; Path=/; HttpOnly")
			w.Header().Set("Location", "http://"+r.Host+"/dashboard")
			w.WriteHeader(http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "upstream says: no such page\n")
		}
	}))
	t.Cleanup(site.Close)
	return site
}

// decoyStand starts a listener that mirrors upstream and returns an HTTPS
// client for it and its address.
func decoyStand(t *testing.T, upstream string) (*http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(Config{
		Addr:          "127.0.0.1:0",
		CertFile:      certFile,
		KeyFile:       keyFile,
		WSPath:        "/ws",
		DecoyUpstream: upstream,
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed test certificate
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, l.Addr().String()
}

type fetched struct {
	status int
	body   string
	header http.Header
}

func fetch(t *testing.T, client *http.Client, rawurl string) fetched {
	t.Helper()
	resp, err := client.Get(rawurl)
	if err != nil {
		t.Fatalf("GET %s: %v", rawurl, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", rawurl, err)
	}
	return fetched{status: resp.StatusCode, body: string(body), header: resp.Header}
}

// The tunnel's path must answer a plain GET exactly the way any other
// unknown path does. This is the whole point of the task: an endpoint found
// by asking for it is not hidden.
func TestTheTunnelsPathLooksLikeAnyOtherPath(t *testing.T) {
	upstream := startUpstream(t)
	client, addr := decoyStand(t, upstream.URL)

	tunnel := fetch(t, client, "https://"+addr+"/ws")
	unknown := fetch(t, client, "https://"+addr+"/no-such-page")
	direct := fetch(t, client, upstream.URL+"/ws")

	if tunnel.status != unknown.status || tunnel.body != unknown.body {
		t.Errorf("the tunnel path answers %d %q, an unknown path answers %d %q",
			tunnel.status, tunnel.body, unknown.status, unknown.body)
	}
	if tunnel.status != direct.status || tunnel.body != direct.body {
		t.Errorf("the tunnel path answers %d %q, the upstream itself answers %d %q",
			tunnel.status, tunnel.body, direct.status, direct.body)
	}
	if tunnel.header.Get("Content-Type") != direct.header.Get("Content-Type") {
		t.Errorf("content type %q against the upstream's %q",
			tunnel.header.Get("Content-Type"), direct.header.Get("Content-Type"))
	}
}

// The front page is the upstream's own, headers included - not a page of
// ours that happens to look like a site.
func TestTheFrontPageIsTheUpstreamsOwn(t *testing.T) {
	upstream := startUpstream(t)
	client, addr := decoyStand(t, upstream.URL)

	through := fetch(t, client, "https://"+addr+"/")
	direct := fetch(t, client, upstream.URL+"/")

	if through.body != direct.body {
		t.Errorf("body through the decoy: %q, from the upstream: %q", through.body, direct.body)
	}
	if through.header.Get("X-Upstream-Marker") != "front-page" {
		t.Error("the upstream's own headers did not survive the proxy")
	}
	if strings.Contains(through.body, "CloudSync") {
		t.Error("the built-in page was served although an upstream is configured")
	}
}

// Nothing about the visitor reaches the upstream. Mirroring someone else's
// site must not hand them the addresses of the people probing this server,
// or of the people using it.
func TestTheUpstreamIsNotToldWhoIsVisiting(t *testing.T) {
	upstream := startUpstream(t)
	client, addr := decoyStand(t, upstream.URL)

	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	header := upstream.lastHeader.Load()
	if header == nil {
		t.Fatal("the upstream saw no request")
	}
	for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		if got := header.Get(name); got != "" {
			t.Errorf("the upstream received %s: %q", name, got)
		}
	}

	// And it is addressed by its own name, so that virtual hosting works
	// and so that it is not handed the name this deployment answers to.
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if host := upstream.lastHost.Load(); host == nil || *host != target.Host {
		t.Errorf("the upstream was addressed as %v, want %q", host, target.Host)
	}
}

// A redirect or a cookie that names the upstream would send the next request
// somewhere else - visible to anyone watching, and a broken cover story for
// the visitor.
func TestTheUpstreamDoesNotNameItselfInRedirectsOrCookies(t *testing.T) {
	upstream := startUpstream(t)
	client, addr := decoyStand(t, upstream.URL)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	got := fetch(t, client, "https://"+addr+"/login")
	if got.status != http.StatusFound {
		t.Fatalf("status %d, want 302", got.status)
	}
	if location := got.header.Get("Location"); strings.Contains(location, target.Host) {
		t.Errorf("Location is %q and names the upstream", location)
	} else if location != "/dashboard" {
		t.Errorf("Location is %q, want the path alone", location)
	}
	for _, cookie := range got.header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(cookie), "domain=") {
			t.Errorf("Set-Cookie is %q and scopes the cookie to the upstream", cookie)
		}
		if !strings.Contains(cookie, "session=abc") || !strings.Contains(cookie, "HttpOnly") {
			t.Errorf("Set-Cookie is %q: the rest of the cookie did not survive", cookie)
		}
	}
}

// An upstream that is down must look like a site whose backend is down, not
// like a proxy that has something else to hide.
func TestAnUnreachableUpstreamLooksLikeAGatewayError(t *testing.T) {
	upstream := startUpstream(t)
	dead := upstream.URL
	upstream.Close()

	client, addr := decoyStand(t, dead)
	got := fetch(t, client, "https://"+addr+"/")
	if got.status != http.StatusBadGateway {
		t.Errorf("status %d, want 502", got.status)
	}
	if !strings.Contains(got.body, "502") {
		t.Errorf("body %q does not look like a gateway error", got.body)
	}
	// Naming a server that the headers do not name is a difference a probe
	// can see, so the page names none.
	for _, name := range []string{"nginx", "Apache", "S5Core"} {
		if strings.Contains(got.body, name) {
			t.Errorf("the gateway error names %s", name)
		}
	}
}

// And the tunnel still works through the same listener: the decoy is what
// everything else gets, not what everything gets.
func TestTheTunnelStillOpensThroughAMirroredSite(t *testing.T) {
	upstream := startUpstream(t)
	dir := t.TempDir()
	certFile, keyFile, err := testcert.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(Config{
		Addr:          "127.0.0.1:0",
		CertFile:      certFile,
		KeyFile:       keyFile,
		WSPath:        "/ws",
		DecoyUpstream: upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	accepted := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			accepted <- err
			return
		}
		_, err = conn.Write(buf)
		accepted <- err
	}()

	client, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + l.Addr().String() + "/ws",
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed test certificate
	})
	if err != nil {
		t.Fatalf("dial the tunnel: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	back := make([]byte, 4)
	if _, err := io.ReadFull(client, back); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(back) != "ping" {
		t.Fatalf("the tunnel returned %q", back)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("the server side of the tunnel: %v", err)
	}

	// The upstream must not have seen the upgrade.
	if n := upstream.requests.Load(); n != 0 {
		t.Errorf("the upstream received %d requests; the tunnel's upgrade was proxied to it", n)
	}
}

func TestAnUpstreamThatCannotBeUsedIsRefusedAtStartup(t *testing.T) {
	for _, raw := range []string{
		"not a url at all",
		"ftp://example.com",
		"https://",
		"https://example.com/?q=1",
		"example.com",
	} {
		if _, err := ValidateUpstream(raw); err == nil {
			t.Errorf("upstream %q was accepted", raw)
		}
	}
	for _, raw := range []string{"", "http://127.0.0.1:8080", "https://example.com", "https://example.com/base"} {
		if _, err := ValidateUpstream(raw); err != nil {
			t.Errorf("upstream %q was refused: %v", raw, err)
		}
	}
}
