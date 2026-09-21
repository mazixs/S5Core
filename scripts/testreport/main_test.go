package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func stream(events ...event) string {
	var b bytes.Buffer
	for _, e := range events {
		_ = json.NewEncoder(&b).Encode(e)
	}
	return b.String()
}

func TestReportLocatesFailureAndKeepsServerDiagnostic(t *testing.T) {
	const pkg = "github.com/mazixs/S5Core/pkg/s5server"
	var out bytes.Buffer
	failed := report(strings.NewReader(stream(
		event{Action: "output", Package: pkg, Test: "TestReplay", Output: "    log.go:12: stage=auth operation=result_write kind=timeout\n"},
		event{Action: "output", Package: pkg, Test: "TestReplay", Output: "    replay_probe_test.go:177: auth read: EOF\n"},
		event{Action: "output", Package: pkg, Test: "TestReplay", Output: "    handler.go:322: server cleanup\n"},
		event{Action: "fail", Package: pkg, Test: "TestReplay"},
		event{Action: "fail", Package: pkg},
	)), &out, true)
	if !failed {
		t.Fatal("failure reported as success")
	}
	for _, want := range []string{"file=pkg/s5server/replay_probe_test.go,line=177", "stage=auth operation=result_write kind=timeout", "test_failure", "TestReplay"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, &out)
		}
	}
	if strings.Count(out.String(), "::error ") != 1 {
		t.Fatalf("duplicate annotation: %s", &out)
	}
}

func TestReportClassifiesPanicsRacesAndBuildFailures(t *testing.T) {
	for _, tc := range []struct{ output, action, kind string }{
		{"panic: runtime error\n", "fail", "panic"},
		{"WARNING: DATA RACE\n", "fail", "data_race"},
		{"compile error\n", "build-fail", "build_failure"},
	} {
		var out bytes.Buffer
		if !report(strings.NewReader(stream(event{Action: "output", Package: "p", Output: tc.output}, event{Action: tc.action, Package: "p"})), &out, true) {
			t.Fatal("failure reported as success")
		}
		if !strings.Contains(out.String(), "title="+tc.kind) {
			t.Fatalf("classification: %s", &out)
		}
	}
}

func TestReportEscapesAnnotationsAndRejectsInvalidStreams(t *testing.T) {
	if got := property("a,b:c%\r\n::error"); got != "a%2Cb%3Ac%25%0D%0A%3A%3Aerror" {
		t.Fatal(got)
	}
	for _, input := range []string{"", "not JSON\n"} {
		var out bytes.Buffer
		if !report(strings.NewReader(input), &out, true) {
			t.Fatalf("accepted %q", input)
		}
	}
	var out bytes.Buffer
	if report(strings.NewReader(stream(event{Action: "pass", Package: "p"})), &out, true) || strings.Contains(out.String(), "::error") {
		t.Fatalf("false failure: %s", &out)
	}
}

func TestBuildEventsUseImportPathAndDoNotDuplicatePackageFailure(t *testing.T) {
	const pkg = "github.com/mazixs/S5Core/pkg/s5server"
	const build = pkg + " [" + pkg + ".test]"
	var out bytes.Buffer
	if !report(strings.NewReader(stream(
		event{Action: "build-output", ImportPath: build, Output: "./broken_test.go:3:33: undefined: symbol\n"},
		event{Action: "build-fail", ImportPath: build},
		event{Action: "fail", Package: pkg, FailedBuild: build},
	)), &out, true) {
		t.Fatal("build failure reported as success")
	}
	if strings.Count(out.String(), "::error ") != 1 || !strings.Contains(out.String(), "file=pkg/s5server/broken_test.go,line=3") {
		t.Fatalf("build annotation: %s", &out)
	}
}

func TestPanicStackLocatesTheTestRatherThanRuntimeCleanup(t *testing.T) {
	const pkg = "github.com/mazixs/S5Core/pkg/s5server"
	var out bytes.Buffer
	if !report(strings.NewReader(stream(
		event{Action: "output", Package: pkg, Test: "TestPanic", Output: "panic: diagnostic probe\n\t/repo/pkg/s5server/panic_test.go:3 +0x25\n\t/usr/local/go/src/testing/testing.go:2036 +0xea\n"},
		event{Action: "fail", Package: pkg, Test: "TestPanic"},
	)), &out, true) {
		t.Fatal("panic reported as success")
	}
	if !strings.Contains(out.String(), "file=/repo/pkg/s5server/panic_test.go,line=3") || !strings.Contains(out.String(), "title=panic") {
		t.Fatalf("panic annotation: %s", &out)
	}
}
