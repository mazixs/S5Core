package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	rmetrics "runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var runtimeFamilies = map[string]dto.MetricType{
	"go_sched_pauses_total_gc_seconds":                dto.MetricType_HISTOGRAM,
	"go_sched_latencies_seconds":                      dto.MetricType_HISTOGRAM,
	"go_gc_cycles_total_gc_cycles_total":              dto.MetricType_COUNTER,
	"go_gc_cycles_forced_gc_cycles_total":             dto.MetricType_COUNTER,
	"go_cpu_classes_gc_total_cpu_seconds_total":       dto.MetricType_COUNTER,
	"go_cpu_classes_gc_mark_assist_cpu_seconds_total": dto.MetricType_COUNTER,
	"go_cpu_classes_gc_mark_idle_cpu_seconds_total":   dto.MetricType_COUNTER,
	"go_cpu_classes_total_cpu_seconds_total":          dto.MetricType_COUNTER,
	"go_gc_heap_live_bytes":                           dto.MetricType_GAUGE,
	"go_gc_limiter_last_enabled_gc_cycle":             dto.MetricType_GAUGE,
	"go_sync_mutex_wait_total_seconds_total":          dto.MetricType_COUNTER,
}

// Families the default registry used to serve and docs/operations/runtime.rules.yml reads.
var compatibilityFamilies = []string{
	"go_gc_duration_seconds",
	"go_memstats_alloc_bytes_total",
	"go_memstats_mallocs_total",
	"go_memstats_sys_bytes",
	"go_memstats_heap_released_bytes",
	"go_goroutines",
	"go_gc_gogc_percent",
	"go_gc_gomemlimit_bytes",
	"go_sched_gomaxprocs_threads",
	"process_start_time_seconds",
	"s5core_build_info",
}

func testMetricsRegistry(t testing.TB) *prometheus.Registry {
	t.Helper()
	r, err := newMetricsRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func gatherRuntime(t testing.TB, r *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	fs, err := r.Gather()
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]*dto.MetricFamily)
	for _, f := range fs {
		m[f.GetName()] = f
	}
	return m
}

func TestRuntimeMetricContract(t *testing.T) {
	kinds := make(map[string]rmetrics.ValueKind)
	for _, d := range rmetrics.All() {
		kinds[d.Name] = d.Kind
	}
	for _, name := range runtimeMetricNames {
		want := rmetrics.KindUint64
		if strings.HasPrefix(name, "/cpu/") || strings.HasPrefix(name, "/sync/") {
			want = rmetrics.KindFloat64
		}
		if strings.HasPrefix(name, "/sched/") {
			want = rmetrics.KindFloat64Histogram
		}
		if kinds[name] != want {
			t.Fatalf("runtime source %s: kind %v, want %v", name, kinds[name], want)
		}
	}
	// Twice: a second registry and exporter must not collide with the first,
	// i.e. nothing is registered globally.
	for range 2 {
		r := testMetricsRegistry(t)
		telemetry, err := setupTelemetry(r)
		if err != nil {
			t.Fatal(err)
		}
		telemetry.RecordBuildInfo("fixture", runtime.Version(), []string{"plain"})
		fs := gatherRuntime(t, r)
		for name, typ := range runtimeFamilies {
			f, ok := fs[name]
			if !ok || f.GetType() != typ {
				t.Fatalf("%s: absent or wrong type", name)
			}
			for _, metric := range f.Metric {
				if len(metric.Label) != 0 {
					t.Fatalf("%s: process metric has application labels", name)
				}
			}
		}
		for _, name := range compatibilityFamilies {
			if fs[name] == nil {
				t.Fatalf("compatibility family %s missing", name)
			}
		}
		if fs["go_memory_classes_heap_objects_bytes"] != nil {
			t.Fatal("runtime allowlist unexpectedly expanded")
		}
	}
}

func TestRuntimeCollectionProgressAndConcurrentScrapes(t *testing.T) {
	r := testMetricsRegistry(t)
	srv := newMetricsServer("", r)
	before := gatherRuntime(t, r)
	keep := make([][]byte, 1024)
	for i := range keep {
		keep[i] = make([]byte, 4096)
	}
	runtime.GC()
	after := gatherRuntime(t, r)
	runtime.KeepAlive(keep)
	for _, name := range []string{"go_gc_cycles_total_gc_cycles_total", "go_gc_cycles_forced_gc_cycles_total", "go_memstats_alloc_bytes_total"} {
		if after[name].Metric[0].Counter.GetValue() <= before[name].Metric[0].Counter.GetValue() {
			t.Errorf("%s did not advance", name)
		}
	}
	if after["go_sched_pauses_total_gc_seconds"].Metric[0].Histogram.GetSampleCount() <= before["go_sched_pauses_total_gc_seconds"].Metric[0].Histogram.GetSampleCount() {
		t.Fatal("GC pause count did not advance")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 8 {
				w := httptest.NewRecorder()
				srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				body := w.Body.String()
				if w.Code != http.StatusOK || !strings.Contains(body, "promhttp_metric_handler_requests_total") {
					t.Error("scrape failed or lost instrumentation")
				}
				// The default registry has no runtime histograms: their presence
				// proves /metrics serves the binary's own registry.
				if !strings.Contains(body, "go_sched_pauses_total_gc_seconds_count") {
					t.Error("/metrics does not serve the binary's registry")
				}
			}
		})
	}
	wg.Wait()
}

// go_sync_mutex_wait_total_seconds_total feeds instance:go_mutex_wait_seconds:rate5m
// in docs/operations/runtime.rules.yml. It must grow with mutex profiling off,
// and reading it must not switch profiling on. A child process runs the
// check: the profiling rate is process-wide, and a parent started with
// -mutexprofile would have it on.
func TestRuntimeMutexWaitWithoutProfiling(t *testing.T) {
	if os.Getenv("S5_MUTEX_FIXTURE") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeMutexWaitWithoutProfiling$")
		cmd.Env = append(os.Environ(), "S5_MUTEX_FIXTURE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("contention fixture: %v\n%s", err, out)
		}
		return
	}
	if runtime.SetMutexProfileFraction(-1) != 0 {
		t.Fatal("mutex profiling must be off")
	}
	r := testMetricsRegistry(t)
	read := func() float64 {
		f := gatherRuntime(t, r)["go_sync_mutex_wait_total_seconds_total"]
		if f == nil {
			t.Fatal("go_sync_mutex_wait_total_seconds_total is not exported")
		}
		return f.Metric[0].Counter.GetValue()
	}
	before := read()
	var mu sync.Mutex
	var wg sync.WaitGroup
	// The runtime samples about one wait in eight, so with 256 contended
	// waits a run where none is sampled is practically impossible.
	for range 16 {
		wg.Go(func() {
			for range 16 {
				mu.Lock()
				time.Sleep(50 * time.Microsecond)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if read() <= before {
		t.Fatal("completed contended waits did not advance the counter")
	}
	if runtime.SetMutexProfileFraction(-1) != 0 {
		t.Fatal("metrics changed profiling settings")
	}
}
