package main

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestPerformanceScheduledDuration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		planned := time.Now().Add(-20 * time.Millisecond)
		got := perfMeasure(planned, func() measurement {
			// Preparation or a scheduler pause can precede measureBody's timer.
			time.Sleep(50 * time.Millisecond)
			return measurement{TotalMS: 1}
		})
		if got.offerDelay != 20*time.Millisecond || got.scheduledTotalMS != 70 || got.TotalMS != 1 {
			t.Fatalf("paced: %+v", got)
		}
		got = perfMeasure(time.Time{}, func() measurement {
			time.Sleep(50 * time.Millisecond)
			return measurement{TotalMS: 3}
		})
		if got.offerDelay != 0 || got.scheduledTotalMS != 3 {
			t.Fatalf("unpaced: %+v", got)
		}
	})
}

func TestPerformanceDurationSetting(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        time.Duration
		invalid     bool
	}{
		{"default", "", 250 * time.Millisecond, false},
		{"set", "15s", 15 * time.Second, false},
		{"zero", "0", 0, true},
		{"negative", "-1s", 0, true},
		{"invalid", "fast", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("S5_PERF_SCRAPE_INTERVAL", tc.value)
			if tc.invalid {
				defer func() {
					if recover() == nil {
						t.Fatal("invalid duration accepted")
					}
				}()
			}
			if got := perfDuration("S5_PERF_SCRAPE_INTERVAL", 250*time.Millisecond); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
