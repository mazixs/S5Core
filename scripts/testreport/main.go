// testreport renders go test -json and emits located GitHub annotations.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

type event struct {
	Action      string
	Package     string
	ImportPath  string
	FailedBuild string
	Test        string
	Output      string
}

type trace struct {
	lines []string
	file  string
	line  string
	kind  string
}

var location = regexp.MustCompile(`^\s*([\w./-]+\.go):(\d+)(?::|\s)`)

func escape(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", "%0A")
}

func property(s string) string {
	return strings.NewReplacer(":", "%3A", ",", "%2C").Replace(escape(s))
}

// failure is one finished failing test or package, ready to print.
type failure struct {
	title, detail string
	file, line    string
}

// collector turns the event stream into failures: it keeps the tail of each
// test's output and reports each failing package once.
type collector struct {
	traces         map[string]*trace
	failedPackages map[string]bool
	failed         bool
}

func newCollector() *collector {
	return &collector{traces: make(map[string]*trace), failedPackages: make(map[string]bool)}
}

// add takes one event and returns the failure it completes, if any.
func (c *collector) add(e event) *failure {
	key := e.Package + "/" + e.Test
	t := c.traces[key]
	if t == nil {
		t = &trace{kind: "test_failure"}
		c.traces[key] = t
	}
	t.absorb(e)
	switch e.Action {
	case "fail", "build-fail":
		c.failed = true
		defer delete(c.traces, key)
		if e.FailedBuild != "" && c.failedPackages[e.FailedBuild] {
			return nil
		}
		if e.Test == "" && c.failedPackages[e.Package] {
			return nil
		}
		c.failedPackages[e.Package] = true
		if e.Action == "build-fail" {
			t.kind = "build_failure"
		} else if e.Test == "" && t.kind == "test_failure" {
			t.kind = "package_failure"
		}
		title := t.kind + ": " + e.Package
		if e.Test != "" {
			title += "/" + e.Test
		}
		return &failure{title: title, detail: strings.Join(t.lines, "\n"), file: t.file, line: t.line}
	case "pass", "skip":
		delete(c.traces, key)
	}
	return nil
}

// absorb keeps the last lines of an event's output, the location of the
// failure and what kind of failure it looks like.
func (t *trace) absorb(e event) {
	for _, line := range strings.Split(strings.TrimSuffix(e.Output, "\n"), "\n") {
		if line == "" {
			continue
		}
		if len(line) > 2000 {
			line = line[:2000] + " [truncated]"
		}
		t.lines = append(t.lines, line)
		if len(t.lines) > 20 {
			t.lines = t.lines[len(t.lines)-20:]
		}
		if m := location.FindStringSubmatch(line); m != nil && (t.file == "" || strings.HasSuffix(m[1], "_test.go")) {
			if path.IsAbs(m[1]) {
				t.file = m[1]
			} else {
				pkg := strings.SplitN(e.Package, " [", 2)[0]
				t.file = path.Join(strings.TrimPrefix(pkg, "github.com/mazixs/S5Core/"), m[1])
			}
			t.line = m[2]
		}
		if strings.Contains(line, "WARNING: DATA RACE") || strings.Contains(line, "race detected during execution of test") {
			t.kind = "data_race"
		}
		if strings.HasPrefix(line, "panic:") || strings.HasPrefix(line, "fatal error:") {
			t.kind = "panic"
		}
	}
}

func report(input io.Reader, output io.Writer, github bool) bool {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	c := newCollector()
	failed := false
	writeFailed := false
	print := func(format string, args ...any) {
		if _, err := fmt.Fprintf(output, format, args...); err != nil {
			writeFailed = true
		}
	}
	events := 0
	for scanner.Scan() {
		var e event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			print("CI_REPORT_ERROR: invalid go test JSON: %v\n", err)
			failed = true
			continue
		}
		events++
		if e.Package == "" {
			e.Package = e.ImportPath
		}
		// Match ordinary go test output: successful test logs stay in the
		// JSON artifact; only failures print their diagnostic context.
		if e.Test == "" {
			print("%s", e.Output)
		}
		if f := c.add(e); f != nil {
			print("\nCI_FAILURE %s\n%s\n", f.title, f.detail)
			if github {
				props := "title=" + property(f.title)
				if f.file != "" {
					props += ",file=" + property(f.file) + ",line=" + f.line
				}
				print("::error %s::%s\n", props, escape(f.detail))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		print("CI_REPORT_ERROR: cannot read go test JSON: %v\n", err)
		failed = true
	}
	if events == 0 {
		print("CI_REPORT_ERROR: go test produced no JSON events\n")
		failed = true
	}
	return failed || c.failed || writeFailed
}

func main() {
	if report(os.Stdin, os.Stdout, os.Getenv("GITHUB_ACTIONS") == "true") {
		os.Exit(1)
	}
}
