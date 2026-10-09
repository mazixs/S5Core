// Package netnstest runs a test again inside a network namespace of its own,
// where it may set what the host does not let it: a sysctl of the namespace,
// loopback, nft rules. The namespace comes from `unshare --user --net` and
// needs no root, the pattern of scripts/matrix. Only tests import it.
// The coverage of a run inside is not counted: -coverprofile gets only the
// run outside, so code reached only inside needs a test on the host as well.
package netnstest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const envInside = "S5CORE_NETNS_TEST"

// Inside reports whether this process is a test run again in its namespace.
func Inside() bool { return os.Getenv(envInside) == "1" }

// FastOpen makes the test run where net.ipv4.tcp_fastopen is 3, the default
// being 1. It returns true when the body of the test is to run in this
// process: the namespace already allows it, or this is the run inside one.
// Otherwise it runs the test again inside a namespace (Namespace).
func FastOpen(t *testing.T) bool {
	t.Helper()
	if !Inside() {
		if mode, err := fastOpenMode(); err == nil && mode&3 == 3 {
			return true
		}
	}
	return Namespace(t)
}

// Namespace makes the test run inside a namespace of its own, with loopback
// up and net.ipv4.tcp_fastopen at 3, whatever the host has: a test that sets
// nft rules or a sysctl calls it. It returns true in the run inside. Outside
// it runs the test again there, reports that run as this test's result and
// returns false; where no namespace can be made (a container whose seccomp
// profile forbids unshare) it skips with the reason.
func Namespace(t *testing.T) bool {
	t.Helper()
	if Inside() {
		if err := setUp(); err != nil {
			t.Skipf("the namespace was not set up: %v", err)
		}
		if mode, err := fastOpenMode(); err != nil || mode&3 != 3 {
			t.Skipf("net.ipv4.tcp_fastopen = %d (%v) inside the namespace", mode, err)
		}
		return true
	}
	ctx := t.Context()
	if d, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, d)
		defer cancel()
	}
	if out, err := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net", "true").CombinedOutput(); err != nil {
		t.Skipf("no namespace can be made: %v %s", err, bytes.TrimSpace(out))
	}
	cmd := exec.CommandContext(ctx, "unshare", "--user", "--map-root-user", "--net",
		os.Args[0], "-test.run", runPattern(t.Name()), "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), envInside+"=1")
	out, err := cmd.CombinedOutput()
	switch {
	case err != nil:
		t.Fatalf("inside a namespace: %v\n%s", err, out)
	case bytes.Contains(out, []byte("--- SKIP: "+t.Name())):
		t.Skipf("inside a namespace:\n%s", out)
	case !bytes.Contains(out, []byte("--- PASS: "+t.Name())):
		t.Fatalf("inside a namespace the test did not run:\n%s", out)
	}
	t.Logf("passed inside a namespace:\n%s", out)
	return false
}

func fastOpenMode() (int, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_fastopen")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// Nft applies rules to the namespace of the test, never to the host's; the
// test calls Namespace first.
func Nft(t *testing.T, rules string) {
	t.Helper()
	if !Inside() {
		t.Fatal("nft is run only inside the test's own namespace (Namespace)")
	}
	cmd := exec.CommandContext(t.Context(), "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		t.Skipf("nft: %v", err)
	}
	if err != nil {
		t.Fatalf("nft: %v %s", err, bytes.TrimSpace(out))
	}
}

func runPattern(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	return strings.Join(parts, "/")
}
