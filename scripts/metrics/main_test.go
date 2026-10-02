package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testsJSON = `{"Action":"run","Package":"github.com/mazixs/S5Core/pkg/a","Test":"TestFast"}
{"Action":"pass","Package":"github.com/mazixs/S5Core/pkg/a","Test":"TestFast","Elapsed":0.01}
{"Action":"pass","Package":"github.com/mazixs/S5Core/pkg/a","Test":"TestSlow","Elapsed":4.5}
{"Action":"pass","Package":"github.com/mazixs/S5Core/pkg/a","Test":"TestSlow/sub","Elapsed":4.4}
{"Action":"skip","Package":"github.com/mazixs/S5Core/pkg/a","Test":"TestSkipped","Elapsed":0}
{"Action":"fail","Package":"github.com/mazixs/S5Core/pkg/b","Test":"TestBroken","Elapsed":1.25}
{"Action":"pass","Package":"github.com/mazixs/S5Core/pkg/a","Elapsed":5}
{"Action":"fail","Package":"github.com/mazixs/S5Core/pkg/b","Elapsed":1.5}
`

const profile = `mode: atomic
github.com/mazixs/S5Core/pkg/a/x.go:10.2,12.3 2 5
github.com/mazixs/S5Core/pkg/a/x.go:14.2,16.3 2 0
github.com/mazixs/S5Core/pkg/a/y.go:3.1,4.2 4 1
github.com/mazixs/S5Core/pkg/b/z.go:3.1,4.2 2 0
`

func TestTestsCountTopLevelTestsAndRankTheSlowest(t *testing.T) {
	s, err := readTests(strings.NewReader(testsJSON))
	if err != nil {
		t.Fatal(err)
	}
	if s.Passed != 2 || s.Failed != 1 || s.Skipped != 1 || s.Packages != 2 || s.Seconds != 6.5 {
		t.Errorf("counts: %+v", s)
	}
	if len(s.Slowest) != 4 || s.Slowest[0].Name != "pkg/a.TestSlow" || s.Slowest[0].Seconds != 4.5 {
		t.Errorf("slowest: %+v", s.Slowest)
	}
}

func TestTestsRejectInvalidJSON(t *testing.T) {
	if _, err := readTests(strings.NewReader("not json\n")); err == nil {
		t.Fatal("invalid go test JSON was accepted")
	}
}

func TestCoverageIsSummedPerPackageAndInTotal(t *testing.T) {
	c, err := readCoverage(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	if c.total.statements != 10 || c.total.covered != 6 {
		t.Errorf("total: %+v", c.total)
	}
	if got := c.packages["pkg/a"]; got.statements != 8 || got.covered != 6 || got.percent() != 75 {
		t.Errorf("pkg/a: %+v", got)
	}
	if got := c.packages["pkg/b"]; got.percent() != 0 {
		t.Errorf("pkg/b: %+v", got)
	}
}

func TestCoverageRejectsAMalformedLine(t *testing.T) {
	for _, line := range []string{"x.go:1.1,2.2 2", "x.go:1.1,2.2 two 1", "nocolon"} {
		if _, err := readCoverage(strings.NewReader("mode: set\n" + line + "\n")); err == nil {
			t.Errorf("%q was accepted", line)
		}
	}
}

func TestBudgetsParseAndRejectNonsense(t *testing.T) {
	b, err := readBudgets(strings.NewReader("# comment\ncoverage total 70.5 # inline\nsize s5core-linux-amd64 123\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if b.coverage["total"] != 70.5 || b.size["s5core-linux-amd64"] != 123 {
		t.Errorf("budgets: %+v", b)
	}
	for _, bad := range []string{"coverage total", "speed total 1", "coverage total x", "size a 1.5", "size a 0", "coverage a 101", "coverage a -1", "size a 1\nsize a 2", "coverage a 1\ncoverage a 2"} {
		if _, err := readBudgets(strings.NewReader(bad + "\n")); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestCheckNamesEveryBrokenBudget(t *testing.T) {
	c, err := readCoverage(strings.NewReader(profile))
	if err != nil {
		t.Fatal(err)
	}
	b := budgets{
		coverage: map[string]float64{"total": 70, "pkg/a": 75, "pkg/b": 10, "pkg/gone": 1},
		size:     map[string]int64{"fits": 100, "grew": 100, "missing": 100},
	}
	got := strings.Join(check(b, &c, map[string]int64{"fits": 100, "grew": 101}), "\n")
	for _, want := range []string{
		"coverage total: 60.00% is below the floor 70.00%",
		"coverage pkg/b: 0.00% is below the floor 10.00%",
		"coverage pkg/gone: package is not in the cover profile",
		"size grew:",
		"size missing: binary was not built",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"pkg/a:", "size fits"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q must pass but was reported:\n%s", unwanted, got)
		}
	}
}

func TestACoverageFloorWithoutAProfileFails(t *testing.T) {
	got := check(budgets{coverage: map[string]float64{"total": 1}}, nil, nil)
	if len(got) != 1 || !strings.Contains(got[0], "no cover profile") {
		t.Errorf("got %v", got)
	}
}

func TestRunWritesTheSummaryAndTheRecord(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bins := filepath.Join(dir, "bin")
	if err := os.Mkdir(bins, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bins, "s5core-linux-amd64"), make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}

	report, err := run(
		write("tests.jsonl", testsJSON), write("coverage.txt", profile), bins,
		write("budgets.txt", "coverage total 50\nsize s5core-linux-amd64 4096\n"), out)
	if err != nil {
		t.Fatalf("budgets are kept, got %v", err)
	}
	for _, want := range []string{"tests: 2 passed", "coverage: 60.0% of 10 statements (floor 50.0%)", "binaries: 1"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
	md, err := os.ReadFile(filepath.Join(out, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## CI metrics", "`pkg/a.TestSlow`", "| `pkg/b` | 2 | 0.0% | - |", "| `s5core-linux-amd64` | 0.00 MB | 0.00 MB | 50.0% |"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("summary lacks %q:\n%s", want, md)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "metrics.json")); err != nil {
		t.Error(err)
	}
}

func TestRunFailsOnABrokenBudgetButStillWritesTheRecord(t *testing.T) {
	dir := t.TempDir()
	cover := filepath.Join(dir, "coverage.txt")
	budgetsFile := filepath.Join(dir, "budgets.txt")
	if err := os.WriteFile(cover, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(budgetsFile, []byte("coverage total 90\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := run("", cover, "", budgetsFile, dir)
	if err == nil || !strings.Contains(err.Error(), "below the floor 90.00%") {
		t.Fatalf("got %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "metrics.json"))
	if err != nil || !strings.Contains(string(raw), "below the floor") {
		t.Errorf("the record lacks the violation: %v %s", err, raw)
	}
}
