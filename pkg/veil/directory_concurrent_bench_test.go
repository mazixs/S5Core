package veil

import (
	"encoding/binary"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// Deliberately overlaps rebuilds and successful lookups. Standalone accept
// and rebuild benchmarks cannot expose time readers spend behind a writer.
func BenchmarkDirectoryLookupDuringRefresh(b *testing.B) {
	members := make([]Member, 32768)
	for i := range members {
		key := make([]byte, MemberKeySize)
		binary.LittleEndian.PutUint64(key, uint64(i))
		members[i] = Member{ID: "member", Key: key}
	}
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	var offset atomic.Int64
	d := &Directory{Now: func() time.Time { return at.Add(time.Duration(offset.Load()) * time.Hour) }}
	if err := d.SetMembers(members); err != nil {
		b.Fatal(err)
	}
	epoch := at.Unix() / EpochSeconds
	tag := memberTag(members[0].Key, epoch)
	stop := make(chan struct{})
	done := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(done)
		for i := int64(1); ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			offset.Store(i % 2)
			d.Refresh()
			if i == 1 {
				close(ready)
			}
			// A short pause avoids an artificial permanently queued writer. The
			// rebuild itself still runs concurrently with many successful lookups.
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	defer func() { close(stop); <-done }()
	<-ready
	// Bound sample memory independently of benchmark calibration.
	samples := make([]time.Duration, 0, 100000)
	iteration := 0
	var longest time.Duration
	for b.Loop() {
		iteration++

		start := time.Now()
		if _, ok := d.lookup(epoch, tag); !ok {
			b.Fatal("member disappeared")
		}
		elapsed := time.Since(start)
		longest = max(longest, elapsed)
		if iteration%128 == 0 && len(samples) < cap(samples) {
			samples = append(samples, elapsed)
		}
	}
	if len(samples) == 0 {
		samples = append(samples, longest)
	}
	b.ReportMetric(float64(longest), "lookup-max-ns")
	b.StopTimer()
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	for name, p := range map[string]float64{"lookup-p50-ns": .5, "lookup-p95-ns": .95, "lookup-p99-ns": .99} {
		b.ReportMetric(float64(samples[int(float64(len(samples)-1)*p)]), name)
	}
}
