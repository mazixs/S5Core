//go:build profiling

package diagnostics

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
)

// Start writes profiles only with -tags=profiling and S5_PROFILE_DIR.
// No HTTP handler is registered. Each process needs a fresh directory and
// graceful termination. These builds are for measurement, not deployment.
func Start() func() {
	dir := os.Getenv("S5_PROFILE_DIR")
	if dir == "" {
		return func() {}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "cpu.pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		panic(err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		panic(err)
	}
	stopTrace := func() {}
	if os.Getenv("S5_TRACE") == "1" {
		tf, e := os.OpenFile(filepath.Join(dir, "trace.out"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			panic(e)
		}
		if e := trace.Start(tf); e != nil {
			_ = tf.Close()
			panic(e)
		}
		stopTrace = func() { trace.Stop(); _ = tf.Close() }
	}
	oldMutex := runtime.SetMutexProfileFraction(10)
	runtime.SetBlockProfileRate(1000000)
	slog.Info("Diagnostic profiles enabled", "directory", dir)
	return func() {
		stopTrace()
		pprof.StopCPUProfile()
		_ = f.Close()
		runtime.SetMutexProfileFraction(oldMutex)
		runtime.SetBlockProfileRate(0)
		for _, name := range []string{"allocs", "heap", "mutex", "block", "goroutine"} {
			out, err := os.OpenFile(filepath.Join(dir, name+".pprof"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				slog.Error("Profile create failed", "error", err)
				continue
			}
			if err := pprof.Lookup(name).WriteTo(out, 0); err != nil {
				slog.Error("Profile write failed", "error", err)
			}
			_ = out.Close()
		}
	}
}
