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

func report(input io.Reader, output io.Writer, github bool) bool {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	traces := make(map[string]*trace)
	failedPackages := make(map[string]bool)
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
		key := e.Package + "/" + e.Test
		t := traces[key]
		if t == nil {
			t = &trace{kind: "test_failure"}
			traces[key] = t
		}
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
		switch e.Action {
		case "fail", "build-fail":
			failed = true
			if e.FailedBuild != "" && failedPackages[e.FailedBuild] {
				delete(traces, key)
				continue
			}
			if e.Test == "" && failedPackages[e.Package] {
				delete(traces, key)
				continue
			}
			failedPackages[e.Package] = true
			if e.Action == "build-fail" {
				t.kind = "build_failure"
			} else if e.Test == "" && t.kind == "test_failure" {
				t.kind = "package_failure"
			}
			title := t.kind + ": " + e.Package
			if e.Test != "" {
				title += "/" + e.Test
			}
			detail := strings.Join(t.lines, "\n")
			print("\nCI_FAILURE %s\n%s\n", title, detail)
			if github {
				props := "title=" + property(title)
				if t.file != "" {
					props += ",file=" + property(t.file) + ",line=" + t.line
				}
				print("::error %s::%s\n", props, escape(detail))
			}
			delete(traces, key)
		case "pass", "skip":
			delete(traces, key)
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
	return failed || writeFailed
}

func main() {
	if report(os.Stdin, os.Stdout, os.Getenv("GITHUB_ACTIONS") == "true") {
		os.Exit(1)
	}
}
