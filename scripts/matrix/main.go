// Command matrix measures HTTP, HTTP/3 (QUIC), TCP and UDP through a SOCKS5
// endpoint, or directly as the control, against origins in its own process.
//
// Every scenario runs under a budget: past it, or after too many failures in a
// row, the scenario stops and is reported as aborted, and the next one runs. A
// scenario that does not return within its budget plus a grace period is hung:
// the partial result is written and the process exits with code 3.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

const exitHung = 3

type scenario struct {
	name string
	run  func() stats
}

func main() {
	socks := flag.String("socks", "", "SOCKS5 address; empty measures directly")
	label := flag.String("label", "direct", "name of this run")
	out := flag.String("out", "", "JSON output file, rewritten after every scenario")
	scale := flag.Float64("scale", 1, "multiplies every request count")
	only := flag.String("only", "", "comma-separated filters: a substring of the name, or =name for that scenario alone")
	list := flag.Bool("list", false, "print the scenarios -only selects and exit")
	budget := flag.Duration("scenario-timeout", 5*time.Minute, "budget of one scenario; past it the scenario stops as aborted")
	grace := flag.Duration("hang-grace", 30*time.Second, "time past the budget after which a scenario that has not returned is hung")
	inRow := flag.Int("max-errors-in-row", 50, "failures in a row that stop a scenario as aborted; 0 disables")
	slowMs := flag.Int("slow-ms", 0, "also report the share of samples slower than p50 plus this many ms")
	soakFor := flag.Duration("soak", 0, "run the soak instead of the probe suite")
	workers := flag.Int("workers", 32, "soak workers")
	idle := flag.Duration("idle", 75*time.Second, "soak idle hold")
	serve := flag.String("serve", "", "only run the origins and write their description to this file")
	listen := flag.String("listen", "127.0.0.1", "origin listen IP with -serve")
	allow := flag.String("allow", "", "comma-separated source prefixes the origins answer besides loopback")
	originFile := flag.String("origin", "", "use remote origins described by this file instead of local ones")
	flag.Parse()

	p := &prober{socks: *socks, dial: dialer(*socks), maxInRow: *inRow, slow: time.Duration(*slowMs) * time.Millisecond}
	suite := p.suite(*scale)
	var chosen []scenario
	for _, s := range suite {
		if *only == "" || slices.ContainsFunc(strings.Split(*only, ","), func(f string) bool { return matches(s.name, f) }) {
			chosen = append(chosen, s)
		}
	}
	if *list {
		for _, s := range chosen {
			fmt.Println(s.name)
		}
		return
	}

	switch {
	case *originFile != "":
		p.o = loadOrigin(*originFile)
	default:
		var prefixes allowed
		for _, a := range strings.Split(*allow, ",") {
			if a = strings.TrimSpace(a); a != "" {
				prefixes = append(prefixes, netip.MustParsePrefix(a))
			}
		}
		p.o = startOrigin(net.ParseIP(*listen), prefixes)
	}
	if *serve != "" {
		b, _ := json.Marshal(p.o)
		must(os.WriteFile(*serve, b, 0o600))
		fmt.Fprintf(os.Stderr, "origins %s %s %s %s\n", p.o.HTTP, p.o.H3, p.o.TCPEcho, p.o.UDPEcho)
		select {}
	}

	w := &writer{path: *out, label: *label, socks: *socks}
	if *soakFor > 0 {
		// The soak is one long scenario: its budget is the load plus the idle hold that runs beside it.
		limit := max(*soakFor, *idle) + *budget
		p.begin(limit)
		guard := w.watch("soak", limit+*grace)
		r := p.soak(*soakFor, *workers, *idle)
		guard.Stop()
		w.soak(r)
		keys := make([]string, 0, len(r.Kinds))
		for k := range r.Kinds {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(os.Stderr, "%s soak %-12s %s\n", *label, k, line(r.Kinds[k]))
		}
		fmt.Fprintf(os.Stderr, "%s idle %v\n", *label, r.Idle)
		return
	}
	for _, s := range chosen {
		fmt.Fprintf(os.Stderr, "%s %-30s start\n", *label, s.name)
		p.begin(*budget)
		guard := w.watch(s.name, *budget+*grace)
		t := time.Now()
		st := s.run()
		guard.Stop()
		st.Seconds = time.Since(t).Seconds()
		st.Aborted = p.end()
		w.add(s.name, st)
		fmt.Fprintf(os.Stderr, "%s %-30s %s  (%.1fs)\n", *label, s.name, line(st), st.Seconds)
	}
	w.finish()
}

func matches(name, filter string) bool {
	if exact, ok := strings.CutPrefix(filter, "="); ok {
		return name == exact
	}
	return filter != "" && strings.Contains(name, filter)
}

func (p *prober) suite(scale float64) []scenario {
	n := func(v int) int { return max(1, int(float64(v)*scale)) }
	// sweepN is ten seconds of 1200-byte datagrams, unscaled: a shorter stream measures slow start, not the rate.
	sweepN := func(mbit float64) int { return int(mbit * 1e6 * 10 / (1200 * 8)) }
	return []scenario{
		{"tcp/connect", func() stats { return p.tcpConnect(n(300)) }},
		{"tcp/echo-64", func() stats { return p.tcpEcho(n(3000), 64) }},
		{"http/small-new", func() stats { return p.webSmall("http", n(300), false) }},
		{"http/small-reuse", func() stats { return p.webSmall("http", n(2000), true) }},
		{"http/large", func() stats { return p.webLarge("http", n(15), false) }},
		{"http/upload", func() stats { return p.webLarge("http", n(15), true) }},
		{"http/small-reuse-under-bulk", func() stats { return p.underLoad("http", func() stats { return p.webSmall("http", n(2000), true) }) }},
		{"https/small-new", func() stats { return p.webSmall("https", n(300), false) }},
		{"https/small-reuse", func() stats { return p.webSmall("https", n(2000), true) }},
		{"https/large", func() stats { return p.webLarge("https", n(15), false) }},
		{"https/upload", func() stats { return p.webLarge("https", n(15), true) }},
		{"https/small-reuse-under-bulk", func() stats { return p.underLoad("https", func() stats { return p.webSmall("https", n(2000), true) }) }},
		{"h2/small-new", func() stats { return p.webSmall("h2", n(300), false) }},
		{"h2/small-reuse", func() stats { return p.webSmall("h2", n(2000), true) }},
		{"h2/small-same-conn-under-bulk", func() stats { return p.h2Shared(n(2000)) }},
		{"h3/small-new", func() stats { return p.h3Small(n(150), false) }},
		{"h3/small-reuse", func() stats { return p.h3Small(n(2000), true) }},
		{"h3/large", func() stats { return p.h3Large(n(10), false) }},
		{"h3/upload", func() stats { return p.h3Large(n(10), true) }},
		{"h3/small-reuse-under-bulk", func() stats { return p.underLoad("http", func() stats { return p.h3Small(n(2000), true) }) }},
		{"udp/rtt-64", func() stats { return p.udpRTT(n(2000), 64) }},
		{"udp/rtt-1200", func() stats { return p.udpRTT(n(2000), 1200) }},
		{"udp/rtt-64-under-bulk", func() stats { return p.underLoad("http", func() stats { return p.udpRTT(n(2000), 64) }) }},
		{"udp/stream-40mbit", func() stats { return p.udpStream(n(20000), 1200, 40) }},
		{"udp/stream-200mbit", func() stats { return p.udpStream(n(40000), 1200, 200) }},
		{"udp/sweep-2mbit", func() stats { return p.udpStream(sweepN(2), 1200, 2) }},
		{"udp/sweep-5mbit", func() stats { return p.udpStream(sweepN(5), 1200, 5) }},
		{"udp/sweep-10mbit", func() stats { return p.udpStream(sweepN(10), 1200, 10) }},
		{"udp/sweep-20mbit", func() stats { return p.udpStream(sweepN(20), 1200, 20) }},
		{"udp/sweep-40mbit", func() stats { return p.udpStream(sweepN(40), 1200, 40) }},
	}
}

// writer keeps the result file current, so a run that is killed or hangs
// still leaves every scenario that finished.
type writer struct {
	mu                 sync.Mutex
	path, label, socks string
	res                map[string]stats
}

func (w *writer) add(name string, st stats) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.res == nil {
		w.res = map[string]stats{}
	}
	w.res[name] = st
	w.flush(false, "")
}

func (w *writer) finish() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flush(true, "")
}

func (w *writer) soak(r soakReport) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.write(map[string]any{"label": w.label, "socks": w.socks, "complete": true, "result": r})
}

// watch exits the process as hung when name has not returned by limit.
func (w *writer) watch(name string, limit time.Duration) *time.Timer {
	return time.AfterFunc(limit, func() {
		w.mu.Lock()
		if w.res == nil {
			w.res = map[string]stats{}
		}
		w.res[name] = stats{Errors: 1, Aborted: "hung", FirstErr: fmt.Sprintf("no return within %s", limit)}
		w.flush(false, name)
		fmt.Fprintf(os.Stderr, "%s %-30s hung: no return within %s\n", w.label, name, limit)
		os.Exit(exitHung)
	})
}

func (w *writer) flush(complete bool, hung string) {
	doc := map[string]any{"label": w.label, "socks": w.socks, "complete": complete, "result": w.res}
	if hung != "" {
		doc["hung"] = hung
	}
	w.write(doc)
}

func (w *writer) write(doc map[string]any) {
	if w.path == "" {
		return
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	tmp := w.path + ".tmp"
	must(os.WriteFile(tmp, b, 0o644))
	must(os.Rename(tmp, w.path))
}

func line(s stats) string {
	l := fmt.Sprintf("n=%d err=%d p50=%.3f p99=%.3f max=%.3f", s.N, s.Errors, s.P50, s.P99, s.Max)
	if s.MBps > 0 {
		l += fmt.Sprintf(" MB/s=%.1f", s.MBps)
	}
	keys := make([]string, 0, len(s.Extra))
	for k := range s.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		l += fmt.Sprintf(" %s=%.3f", k, s.Extra[k])
	}
	if s.Aborted != "" {
		l += " aborted=" + s.Aborted
	}
	if s.FirstErr != "" {
		l += " first_err=" + s.FirstErr
	}
	return l
}
