// Package arch holds no code. It holds the one test that says what this
// repository's packages are allowed to know about each other.
//
// Plan task Ф6-2 split the layers apart; its gate is "the imports confirm the
// separation". A gate checked by reading is a gate that reopens in six
// months, so it is checked by `go list` instead: the rules below are the
// separation, and a future import that breaks one fails here by name.
package arch

import (
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/mazixs/S5Core"

// rule is one package and what it may not reach, directly or transitively.
type rule struct {
	// pkg is a package pattern in the go list sense, so ./pkg/transport/...
	// covers every transport at once.
	pkg string
	// why states the separation in one line; it is what a failure prints.
	why string
	// forbidden lists import path prefixes that must not appear anywhere in
	// the package's dependency tree.
	forbidden []string
	// allowed lists prefixes that are exempt from the forbidden list. They
	// are the deliberate exceptions, and each one needs a reason in the
	// comment above it.
	allowed []string
}

var rules = []rule{
	{
		pkg: module + "/internal/socks5",
		why: "the SOCKS5 codec parses messages; it does not meter traffic, " +
			"count metrics or know which transport carried the bytes",
		forbidden: []string{
			"go.opentelemetry.io/",
			"github.com/prometheus/",
			module + "/pkg/obfs",
			module + "/pkg/veil",
			module + "/pkg/transport/",
			module + "/pkg/s5server",
			module + "/internal/userstore",
			module + "/internal/identity",
		},
	},
	{
		pkg: module + "/pkg/transport/...",
		why: "a transport delivers bytes; the obfuscation of what is inside " +
			"them belongs to pkg/obfs and the identity behind them to the server",
		forbidden: []string{
			"go.opentelemetry.io/",
			module + "/pkg/obfs",
			module + "/pkg/veil",
			module + "/internal/socks5",
			module + "/internal/relay",
			module + "/internal/identity",
			module + "/internal/userstore",
			module + "/pkg/s5server",
		},
		// internal/utls is the TLS stack the WebSocket transport dials with.
		// TLS is this transport's own wire format - a WSS connection without
		// it does not exist - and not the cryptography that hides the payload,
		// which is what the rule above is about.
		allowed: []string{module + "/internal/utls"},
	},
	{
		pkg: module + "/internal/relay",
		why: "the relay copies and meters bytes; it neither speaks SOCKS5 " +
			"nor decides who is allowed in",
		forbidden: []string{
			"go.opentelemetry.io/",
			module + "/internal/socks5",
			module + "/internal/identity",
			module + "/internal/userstore",
			module + "/pkg/",
		},
	},
	{
		pkg: module + "/internal/identity",
		why: "the access decision is given a credential store and returns " +
			"one; it does not know what a listener, a codec or a metric is",
		forbidden: []string{
			"go.opentelemetry.io/",
			module + "/internal/socks5",
			module + "/internal/relay",
			module + "/pkg/",
		},
	},
	{
		pkg: module + "/internal/session",
		why: "the connection state machine is the vocabulary everything else " +
			"reports in, so it may depend on nothing of ours at all",
		forbidden: []string{
			"go.opentelemetry.io/",
			module + "/internal/",
			module + "/pkg/",
		},
	},
	{
		pkg: module + "/internal/tcptune",
		why: "socket tuning is reached through wrappers it knows only by " +
			"NetConn and Unwrap, so it may depend on nothing of ours",
		forbidden: []string{
			module + "/internal/",
			module + "/pkg/",
		},
	},
	{
		pkg: module + "/pkg/obfs",
		why: "the obfuscation format carries bytes over any transport and " +
			"knows nothing about what they mean",
		forbidden: []string{
			"go.opentelemetry.io/",
			module + "/internal/socks5",
			module + "/internal/relay",
			module + "/internal/identity",
			module + "/internal/userstore",
			module + "/pkg/transport/",
			module + "/pkg/s5server",
		},
	},
}

func TestTheLayersDoNotReachIntoEachOther(t *testing.T) {
	for _, r := range rules {
		t.Run(r.pkg, func(t *testing.T) {
			for _, dep := range deps(t, r.pkg) {
				if exempt(dep, r.allowed) {
					continue
				}
				for _, bad := range r.forbidden {
					if strings.HasPrefix(dep, bad) {
						t.Errorf("%s reaches %s, which breaks the separation:\n\t%s",
							r.pkg, dep, r.why)
					}
				}
			}
		})
	}
}

func exempt(dep string, allowed []string) bool {
	for _, a := range allowed {
		if strings.HasPrefix(dep, a) {
			return true
		}
	}
	return false
}

// deps lists everything the pattern's packages import, transitively, minus
// the standard library and the packages matched by the pattern itself.
func deps(t *testing.T, pattern string) []string {
	t.Helper()

	self := map[string]bool{}
	for _, p := range list(t, "{{.ImportPath}}", pattern) {
		self[p] = true
	}

	var out []string
	for _, p := range list(t, "{{if not .Standard}}{{.ImportPath}}{{end}}", "-deps", pattern) {
		if !self[p] {
			out = append(out, p)
		}
	}
	return out
}

func list(t *testing.T, format string, args ...string) []string {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-f", format}, args...)...)
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %v: %v\n%s", args, err, out)
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			paths = append(paths, line)
		}
	}
	return paths
}
