package tlsdecoy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mazixs/S5Core/internal/testcert"
	"github.com/mazixs/S5Core/pkg/transport/ws"
)

// F16 in docs/reports/code-quality-audit-2026-09-20.md. ValidatePath decided
// with a handful of string tests, and net/http decides with a pattern
// language: "/{" passed validation and panicked at registration, with the
// socket already open. These tests are about the two things the endpoint has
// to be - a pattern net/http accepts, and a pattern that matches exactly the
// path ws.Upgrader compares against - because being only the first is what
// the old checks confirmed.

// acceptedPaths are what a deployment may configure. They are also the input
// to the property below, so adding one here is a claim that it works
// end to end.
var acceptedPaths = []string{
	"/ws",
	"/api/v1/stream",
	"/a-b_c.d~e",
	"/ws2",
	"/deeply/nested/endpoint",
}

// refusedPaths are what it may not, each with the word its error must say.
var refusedPaths = []struct {
	path string
	says string
}{
	// The finding itself: accepted by the old checks, panic at registration.
	{"/{", "wildcard"},
	{"/ws/{", "wildcard"},
	// A pattern net/http accepts and the upgrade then refuses: the mux
	// matches /ws/anything, the upgrader compares against /ws/{id}.
	{"/ws/{id}", "wildcard"},
	{"/ws/{id...}", "wildcard"},
	{"/ws/{$}", "wildcard"},
	// Not canonical: net/http redirects these, so the path the upgrader is
	// compared against is never the one configured.
	{"/a//b", "canonical"},
	{"/a/../b", "canonical"},
	{"/a/./b", "canonical"},
	// Percent-encoded: r.URL.Path is decoded, so this can only ever be
	// compared against the literal characters % 2 F.
	{"/ws%2F", "percent-encoded"},
	{"/ws%20x", "percent-encoded"},
	// Neither of these is part of a path at all.
	{"/ws?x=1", "not part of a path"},
	{"/ws#frag", "not part of a path"},
	// A control character survives no round trip worth relying on.
	{"/w\x01s", "control character"},
	// The pattern language's other two parts: a method and a host. Both are
	// separated by a space, which is refused for its own reason.
	{"GET /ws", "must start with /"},
	{"/example.com/ws x", "whitespace"},
}

func TestAPathThatNetHTTPWouldRejectIsRefusedBeforeTheSocketOpens(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	// A fixed port, so that "the listener was not left open" is a question
	// with an answer: if NewListener kept the socket, listening again fails.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	for _, tc := range refusedPaths {
		t.Run(tc.path, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("path %q panicked instead of returning an error: %v", tc.path, r)
				}
			}()

			l, err := NewListener(Config{
				Addr:     addr,
				CertFile: certFile,
				KeyFile:  keyFile,
				WSPath:   tc.path,
			})
			if err == nil {
				_ = l.Close()
				t.Fatalf("path %q was accepted", tc.path)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not explain the problem (looking for %q)", err, tc.says)
			}

			// The socket must not have been taken: a configuration error is
			// answered before anything is acquired.
			again, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("after refusing %q the address %s is still held: %v", tc.path, addr, err)
			}
			_ = again.Close()
		})
	}
}

// The property: every accepted path registers without a panic, catches
// exactly itself, and catches nothing else. The last part is what separates
// this from "net/http accepted the pattern" - a wildcard is accepted and
// matches paths the upgrade will refuse.
func TestAnAcceptedPathMatchesItselfAndNothingElse(t *testing.T) {
	for _, path := range acceptedPaths {
		t.Run(path, func(t *testing.T) {
			if err := ValidatePath(path); err != nil {
				t.Fatalf("ValidatePath(%q) = %v", path, err)
			}

			var served string
			mux := http.NewServeMux()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("registering the accepted path %q panicked: %v", path, r)
					}
				}()
				mux.HandleFunc(path, func(http.ResponseWriter, *http.Request) { served = "tunnel" })
			}()
			mux.HandleFunc("/", func(http.ResponseWriter, *http.Request) { served = "decoy" })

			for _, tc := range []struct {
				request string
				want    string
			}{
				{path, "tunnel"},
				{path + "/x", "decoy"},
				{path + "x", "decoy"},
				{"/", "decoy"},
				{"/elsewhere", "decoy"},
			} {
				served = ""
				mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.request, nil))
				if served != tc.want {
					t.Errorf("with the endpoint at %q, a request for %q reached the %s, want the %s",
						path, tc.request, served, tc.want)
				}
			}
		})
	}
}

// A pattern net/http accepts is not the same thing as a path the two sides
// agree on, and a tunnel registered on a path the upgrade never matches is
// worse than a refused configuration: it starts, it listens, and it never
// answers. This is that case, stated with the encoding net/http decodes.
func TestAPatternNetHTTPAcceptsCanStillBeUnreachable(t *testing.T) {
	const encoded = "/%41" // "/A" once decoded

	if err := registrable(encoded); err != nil {
		t.Fatalf("net/http refuses %q outright, so this test no longer says anything: %v", encoded, err)
	}
	r := httptest.NewRequest(http.MethodGet, encoded, nil)
	if r.URL.Path == encoded {
		t.Skipf("net/http no longer decodes %q into r.URL.Path", encoded)
	}

	// Registered and unreachable: the mux answers, the upgrade's comparison
	// against the configured string cannot.
	if err := ValidatePath(encoded); err == nil {
		t.Fatalf("ValidatePath(%q) = nil, but r.URL.Path for that request is %q, "+
			"so the upgrade would refuse every request the mux sends it", encoded, r.URL.Path)
	}
}

// End to end on a path that is legal but not the obvious one: the upgrade has
// to happen on exactly the configured path and nowhere near it.
func TestAnUnusualButLegalPathCarriesTheTunnel(t *testing.T) {
	certFile, keyFile, err := testcert.Generate(t.TempDir())
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	const path = "/a-b_c.d~e"
	l, err := NewListener(Config{
		Addr:      "127.0.0.1:0",
		CertFile:  certFile,
		KeyFile:   keyFile,
		WSPath:    path,
		DecoyHTML: "<html><body>decoy</body></html>",
	})
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	addr := l.Addr().String()
	client, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + addr + path,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("dial the configured path: %v", err)
	}
	defer client.Close()

	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the upgrade on the configured path never reached the listener")
	}

	// One character away is the decoy, not the tunnel.
	if _, err := ws.Dial(ws.DialOpts{
		URL:       "wss://" + addr + path + "x",
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}); err == nil {
		t.Fatal("an upgrade one character away from the endpoint succeeded")
	}
}
