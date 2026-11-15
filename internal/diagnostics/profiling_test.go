//go:build profiling

package diagnostics

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Every profile is written, the goroutine leak one among them, and the mutex
// fraction the process had is given back. The profiles run in a process of
// their own, as Start may run once.
func TestProfilingWritesEveryProfile(t *testing.T) {
	if os.Getenv("S5_PROFILE_FIXTURE") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProfilingWritesEveryProfile$")
		cmd.Env = append(os.Environ(), "S5_PROFILE_FIXTURE=1", "S5_PROFILE_DIR="+t.TempDir())
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("profiling fixture: %v\n%s", err, output)
		}
		return
	}
	runtime.SetMutexProfileFraction(3)
	stop := Start()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 32 {
				mu.Lock()
				time.Sleep(100 * time.Microsecond) // contention for the mutex profile
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	stop()
	if runtime.SetMutexProfileFraction(-1) != 3 {
		t.Fatal("the mutex fraction was not given back")
	}
	for _, name := range []string{"cpu", "heap", "mutex", "block", "goroutine", "goroutineleak"} {
		info, err := os.Stat(filepath.Join(os.Getenv("S5_PROFILE_DIR"), name+".pprof"))
		if err != nil || info.Size() == 0 {
			t.Errorf("profile %s missing or empty: %v", name, err)
		}
	}
}
