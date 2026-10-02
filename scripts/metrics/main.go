// metrics turns what scripts/pre-commit.sh leaves behind (go test -json, the
// cover profile, the release binaries) into a markdown summary, a JSON record
// and a verdict on the budgets file. The same files are produced locally and
// in CI, so a number on a pull request can be reproduced with one command.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const modulePrefix = "github.com/mazixs/S5Core/"

const slowestTests = 10

type timed struct {
	Name    string  `json:"name"`
	Seconds float64 `json:"seconds"`
}

type testStats struct {
	Passed   int     `json:"passed"`
	Failed   int     `json:"failed"`
	Skipped  int     `json:"skipped"`
	Packages int     `json:"packages"`
	Seconds  float64 `json:"package_seconds"`
	Slowest  []timed `json:"slowest"`
}

type blocks struct{ statements, covered int }

func (b blocks) percent() float64 {
	if b.statements == 0 {
		return 100
	}
	return 100 * float64(b.covered) / float64(b.statements)
}

type coverage struct {
	total    blocks
	packages map[string]blocks
}

type budgets struct {
	coverage map[string]float64
	size     map[string]int64
}

type record struct {
	Tests      *testStats         `json:"tests,omitempty"`
	Coverage   map[string]float64 `json:"coverage,omitempty"`
	Binaries   map[string]int64   `json:"binaries,omitempty"`
	Violations []string           `json:"violations"`
}

type testEvent struct {
	Action  string
	Package string
	Test    string
	Elapsed float64
}

// readTests counts finished top-level tests and sums the time of the
// packages. Subtests are left out: their parent already includes them.
func readTests(r io.Reader) (testStats, error) {
	var s testStats
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var e testEvent
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return s, fmt.Errorf("invalid go test JSON: %w", err)
		}
		if e.Action != "pass" && e.Action != "fail" && e.Action != "skip" {
			continue
		}
		if e.Test == "" {
			if e.Package != "" {
				s.Packages++
				s.Seconds += e.Elapsed
			}
			continue
		}
		if strings.Contains(e.Test, "/") {
			continue
		}
		switch e.Action {
		case "pass":
			s.Passed++
		case "fail":
			s.Failed++
		case "skip":
			s.Skipped++
		}
		s.Slowest = append(s.Slowest, timed{strings.TrimPrefix(e.Package, modulePrefix) + "." + e.Test, e.Elapsed})
	}
	if err := scanner.Err(); err != nil {
		return s, err
	}
	sort.SliceStable(s.Slowest, func(i, j int) bool { return s.Slowest[i].Seconds > s.Slowest[j].Seconds })
	if len(s.Slowest) > slowestTests {
		s.Slowest = s.Slowest[:slowestTests]
	}
	return s, nil
}

// readCoverage reads a cover profile: "file:start,end statements count".
func readCoverage(r io.Reader) (coverage, error) {
	c := coverage{packages: map[string]blocks{}}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		colon := strings.LastIndexByte(line, ':')
		if colon < 0 {
			return c, fmt.Errorf("invalid cover profile line %q", line)
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) != 3 {
			return c, fmt.Errorf("invalid cover profile line %q", line)
		}
		statements, err1 := strconv.Atoi(fields[1])
		count, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return c, fmt.Errorf("invalid cover profile line %q", line)
		}
		pkg := strings.TrimPrefix(path.Dir(line[:colon]), modulePrefix)
		b := c.packages[pkg]
		b.statements += statements
		c.total.statements += statements
		if count > 0 {
			b.covered += statements
			c.total.covered += statements
		}
		c.packages[pkg] = b
	}
	return c, scanner.Err()
}

// readBudgets reads lines "coverage <total|package> <percent>" and
// "size <binary> <bytes>"; '#' starts a comment.
func readBudgets(r io.Reader) (budgets, error) {
	b := budgets{coverage: map[string]float64{}, size: map[string]int64{}}
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return b, fmt.Errorf("budgets line %d: want 3 fields, got %q", n, strings.TrimSpace(line))
		}
		switch fields[0] {
		case "coverage":
			v, err := strconv.ParseFloat(fields[2], 64)
			if err != nil {
				return b, fmt.Errorf("budgets line %d: %w", n, err)
			}
			if v < 0 || v > 100 {
				return b, fmt.Errorf("budgets line %d: coverage %v is outside 0-100", n, v)
			}
			if _, dup := b.coverage[fields[1]]; dup {
				return b, fmt.Errorf("budgets line %d: coverage %s is set twice", n, fields[1])
			}
			b.coverage[fields[1]] = v
		case "size":
			v, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				return b, fmt.Errorf("budgets line %d: %w", n, err)
			}
			if v <= 0 {
				return b, fmt.Errorf("budgets line %d: size %d is not positive", n, v)
			}
			if _, dup := b.size[fields[1]]; dup {
				return b, fmt.Errorf("budgets line %d: size %s is set twice", n, fields[1])
			}
			b.size[fields[1]] = v
		default:
			return b, fmt.Errorf("budgets line %d: unknown kind %q", n, fields[0])
		}
	}
	return b, scanner.Err()
}

func readSizes(dir string) (map[string]int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		sizes[e.Name()] = info.Size()
	}
	return sizes, nil
}

// check names every budget that is broken. A budget with nothing to measure
// is broken too: a package that lost its tests or a binary that stopped
// building must not pass by disappearing from the input.
func check(b budgets, c *coverage, sizes map[string]int64) []string {
	var out []string
	for _, name := range sortedKeys(b.coverage) {
		floor := b.coverage[name]
		if c == nil {
			out = append(out, fmt.Sprintf("coverage %s: no cover profile", name))
			continue
		}
		got := c.total
		if name != "total" {
			var ok bool
			if got, ok = c.packages[name]; !ok {
				out = append(out, fmt.Sprintf("coverage %s: package is not in the cover profile", name))
				continue
			}
		}
		if got.percent() < floor {
			out = append(out, fmt.Sprintf("coverage %s: %.2f%% is below the floor %.2f%%", name, got.percent(), floor))
		}
	}
	for _, name := range sortedKeys(b.size) {
		limit := b.size[name]
		got, ok := sizes[name]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("size %s: binary was not built", name))
		case got > limit:
			out = append(out, fmt.Sprintf("size %s: %s exceeds the budget %s", name, megabytes(got), megabytes(limit)))
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func megabytes(n int64) string { return fmt.Sprintf("%.2f MB", float64(n)/1e6) }

func summary(w *strings.Builder, t *testStats, c *coverage, b budgets, sizes map[string]int64, violations []string) {
	fmt.Fprintln(w, "## CI metrics")
	if t != nil {
		fmt.Fprintf(w, "\n### Tests\n\n%d passed, %d failed, %d skipped in %d packages; the packages took %.0f s together.\n",
			t.Passed, t.Failed, t.Skipped, t.Packages, t.Seconds)
		if len(t.Slowest) > 0 {
			fmt.Fprint(w, "\n| slowest tests | seconds |\n|---|---:|\n")
			for _, s := range t.Slowest {
				fmt.Fprintf(w, "| `%s` | %.2f |\n", s.Name, s.Seconds)
			}
		}
	}
	if c != nil {
		fmt.Fprintf(w, "\n### Coverage\n\n**%.1f%%** of %d statements%s.\n", c.total.percent(), c.total.statements, floorNote(b.coverage, "total"))
		names := sortedKeys(c.packages)
		sort.SliceStable(names, func(i, j int) bool { return c.packages[names[i]].percent() < c.packages[names[j]].percent() })
		fmt.Fprint(w, "\n<details><summary>by package, lowest first</summary>\n\n| package | statements | coverage | floor |\n|---|---:|---:|---:|\n")
		for _, name := range names {
			p := c.packages[name]
			floor := "-"
			if v, ok := b.coverage[name]; ok {
				floor = fmt.Sprintf("%.1f%%", v)
			}
			fmt.Fprintf(w, "| `%s` | %d | %.1f%% | %s |\n", name, p.statements, p.percent(), floor)
		}
		fmt.Fprint(w, "\n</details>\n")
	}
	if len(sizes) > 0 {
		fmt.Fprint(w, "\n### Release binaries\n\n| binary | size | budget | headroom |\n|---|---:|---:|---:|\n")
		for _, name := range sortedKeys(sizes) {
			budget, headroom := "-", "-"
			if limit, ok := b.size[name]; ok {
				budget = megabytes(limit)
				headroom = fmt.Sprintf("%.1f%%", 100*float64(limit-sizes[name])/float64(limit))
			}
			fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", name, megabytes(sizes[name]), budget, headroom)
		}
	}
	if len(violations) > 0 {
		fmt.Fprint(w, "\n### Broken budgets\n\n")
		for _, v := range violations {
			fmt.Fprintf(w, "- %s\n", v)
		}
	}
}

func floorNote(floors map[string]float64, name string) string {
	if v, ok := floors[name]; ok {
		return fmt.Sprintf(" (floor %.1f%%)", v)
	}
	return ""
}

func open[T any](file string, read func(io.Reader) (T, error)) (*T, error) {
	if file == "" {
		return nil, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &v, nil
}

// run writes summary.md and metrics.json to outDir and returns a short plain
// report. The error names every broken budget.
func run(testsFile, coverFile, binsDir, budgetsFile, outDir string) (string, error) {
	t, err := open(testsFile, readTests)
	if err != nil {
		return "", err
	}
	c, err := open(coverFile, readCoverage)
	if err != nil {
		return "", err
	}
	b, err := open(budgetsFile, readBudgets)
	if err != nil {
		return "", err
	}
	if b == nil {
		b = &budgets{}
	}
	var sizes map[string]int64
	if binsDir != "" {
		if sizes, err = readSizes(binsDir); err != nil {
			return "", err
		}
	}

	violations := check(*b, c, sizes)
	var md strings.Builder
	summary(&md, t, c, *b, sizes, violations)

	rec := record{Tests: t, Binaries: sizes, Violations: violations}
	if rec.Violations == nil {
		rec.Violations = []string{}
	}
	if c != nil {
		rec.Coverage = map[string]float64{"total": c.total.percent()}
		for name, p := range c.packages {
			rec.Coverage[name] = p.percent()
		}
	}
	if outDir != "" {
		raw, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(outDir, "summary.md"), []byte(md.String()), 0o644); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(outDir, "metrics.json"), append(raw, '\n'), 0o644); err != nil {
			return "", err
		}
	}

	var plain strings.Builder
	if t != nil {
		fmt.Fprintf(&plain, "tests: %d passed, %d failed, %d skipped, packages %.0f s\n", t.Passed, t.Failed, t.Skipped, t.Seconds)
	}
	if c != nil {
		fmt.Fprintf(&plain, "coverage: %.1f%% of %d statements%s\n", c.total.percent(), c.total.statements, floorNote(b.coverage, "total"))
	}
	if len(sizes) > 0 {
		fmt.Fprintf(&plain, "binaries: %d, largest %s\n", len(sizes), megabytes(largest(sizes)))
	}
	if len(violations) > 0 {
		return plain.String(), errors.New(strings.Join(violations, "\n"))
	}
	return plain.String(), nil
}

func largest(sizes map[string]int64) int64 {
	var top int64
	for _, n := range sizes {
		top = max(top, n)
	}
	return top
}

func main() {
	tests := flag.String("tests", "", "go test -json output")
	cover := flag.String("coverage", "", "cover profile")
	bins := flag.String("bins", "", "directory with the release binaries")
	budgetsFile := flag.String("budgets", "", "budgets file")
	out := flag.String("out", "", "directory for summary.md and metrics.json")
	flag.Parse()
	report, err := run(*tests, *cover, *bins, *budgetsFile, *out)
	fmt.Print(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "metrics: %v\n", err)
		os.Exit(1)
	}
}
