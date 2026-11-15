package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// runtimeMetricNames are runtime/metrics sources exported on top of the Go
// collector's defaults (GC summary, MemStats, GOGC, GOMEMLIMIT, GOMAXPROCS).
// All of them are process-wide and carry no labels of their own.
var runtimeMetricNames = []string{
	"/sched/pauses/total/gc:seconds",
	"/sched/latencies:seconds",
	"/gc/cycles/total:gc-cycles",
	"/gc/cycles/forced:gc-cycles",
	"/cpu/classes/gc/total:cpu-seconds",
	"/cpu/classes/gc/mark/assist:cpu-seconds",
	"/cpu/classes/gc/mark/idle:cpu-seconds",
	"/cpu/classes/total:cpu-seconds",
	"/gc/heap/live:bytes",
	"/gc/limiter/last-enabled:gc-cycle",
	"/sync/mutex/wait/total:seconds",
}

func newRuntimeCollector() prometheus.Collector {
	quoted := make([]string, len(runtimeMetricNames))
	for i, name := range runtimeMetricNames {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(
		collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile("^(?:" + strings.Join(quoted, "|") + ")$")},
	))
}

// newMetricsRegistry is the registry of the standalone binary. Go and process
// collectors live here, not in pkg/s5server: an embedding application owns
// its own process metrics.
func newMetricsRegistry() (*prometheus.Registry, error) {
	r := prometheus.NewRegistry()
	for _, c := range []prometheus.Collector{newRuntimeCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})} {
		if err := r.Register(c); err != nil {
			return nil, fmt.Errorf("register process metrics: %w", err)
		}
	}
	return r, nil
}
