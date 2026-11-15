package diagnostics

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime/trace"
	"sync"
	"time"
	"uuid"

	"github.com/mazixs/S5Core/internal/privatefs"
)

const (
	// envDir turns the recorder on: the directory it keeps incidents in.
	envDir = "S5_DIAGNOSTICS_DIR"
	// envRunID names the run in every manifest, so incidents of both ends
	// of a test can be matched; a UUID of its own otherwise.
	envRunID = "S5_DIAGNOSTICS_RUN_ID"
	// envTrace set to 1 keeps a flight recorder trace for every incident.
	envTrace = "S5_DIAGNOSTICS_TRACE"

	runIDMaxBytes = 256
	// stopWait bounds how long stopping waits for the worker: a file system
	// call cannot be cancelled.
	stopWait = 2 * time.Second
)

// StartLatency turns the latency recorder on when S5_DIAGNOSTICS_DIR is set
// and returns what stops it. The recorder starts in the background: a slow
// file system holds up neither the start of the process nor its forwarding,
// and a failure is one line in the log with the forwarding left alone. A
// recorder that becomes ready after stop has been called stops itself.
func StartLatency() (stop func()) {
	dir := os.Getenv(envDir)
	if dir == "" {
		return func() {}
	}
	runID, flight := os.Getenv(envRunID), os.Getenv(envTrace) == "1"
	var mu sync.Mutex
	var stopped bool
	var running *recorder
	go func() {
		r, err := openRecorder(dir, runID, flight)
		if err != nil {
			slog.Error("Latency diagnostics are off", "dir", dir, "error", err)
			return
		}
		mu.Lock()
		late := stopped || !current.CompareAndSwap(nil, r)
		if !late {
			running = r
		}
		mu.Unlock()
		if late {
			r.close()
			return
		}
		slog.Info("Latency diagnostics are on", "dir", dir, "run_id", r.runID, "trace", flight)
	}()
	return func() {
		mu.Lock()
		stopped = true
		r := running
		mu.Unlock()
		if r != nil {
			current.CompareAndSwap(r, nil)
			r.close()
		}
	}
}

// openRecorder makes the recorder for dir and starts its worker. dir is
// created private, or must be private already.
func openRecorder(dir, runID string, flight bool) (*recorder, error) {
	r, err := newDirRecorder(dir, runID, flight)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go r.run(ctx)
	return r, nil
}

// newDirRecorder is openRecorder without the worker, which a test drives
// with step instead.
func newDirRecorder(dir, runID string, flight bool) (*recorder, error) {
	if len(runID) > runIDMaxBytes {
		return nil, errors.New("S5_DIAGNOSTICS_RUN_ID is longer than 256 bytes")
	}
	if err := privatefs.MkdirAll(dir); err != nil {
		return nil, err
	}
	if err := privatefs.CheckDir(dir); err != nil {
		return nil, err
	}
	r := newRecorder()
	r.dir, r.runID, r.bootID = dir, runID, uuid.New().String()
	if r.runID == "" {
		r.runID = uuid.New().String()
	}
	if flight {
		r.flight = trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: traceMinAge, MaxBytes: traceMaxBytes})
		if err := r.flight.Start(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// close stops the recorder and waits a bounded time for its worker to save
// the incident it is writing.
func (r *recorder) close() {
	r.stopped.Store(true)
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(stopWait):
		slog.Warn("Latency diagnostics did not finish writing in time", "dir", r.dir)
	}
}

func (r *recorder) run(ctx context.Context) {
	defer close(r.done)
	t := time.NewTicker(sampleInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.shutdown()
			return
		case now := <-t.C:
			if !r.step(now) {
				r.shutdown()
				return
			}
		}
	}
}

// step is one tick of the worker: the room now and then, the samples, the
// incident being written, then the triggers, the operator's marker first.
// It returns false when the recorder has to stop.
func (r *recorder) step(now time.Time) bool {
	r.ticks++
	if r.ticks%diskCheckEvery == 0 {
		if _, err := r.makeRoom(1); err != nil {
			r.giveUp(err)
			return false
		}
	}
	sp, more := r.tick(now)
	if p := r.pending; p != nil {
		r.drain(p)
		if now.Sub(p.at) >= postWindow {
			r.finish(p, false)
		}
	}
	if id, ok := r.pollMarker(); ok {
		r.trigger(now, id, true, spike{})
	}
	if sp.reason != 0 {
		r.trigger(now, uuid.New().String(), false, sp)
	}
	if more > 0 {
		r.reject(more)
	}
	return !r.stopped.Load()
}

// giveUp stops the recorder for good when the directory has no room left:
// one line in the log, and the wrappers pass every call through. An
// incident being written stays as its partial file.
func (r *recorder) giveUp(err error) {
	if r.stopped.Swap(true) {
		return
	}
	current.CompareAndSwap(r, nil)
	if p := r.pending; p != nil {
		r.pending = nil
		_ = p.w.Flush()
		_ = p.f.Close()
		r.health.failed++
	}
	slog.Error("Latency diagnostics stopped", "dir", r.dir, "error", err)
}

// shutdown saves the incident being written, waits for its trace and stops
// the flight recorder.
func (r *recorder) shutdown() {
	if p := r.pending; p != nil {
		r.finish(p, true)
	}
	r.traces.Wait()
	if r.flight != nil {
		r.flight.Stop()
	}
}
