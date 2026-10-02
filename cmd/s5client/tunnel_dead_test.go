package main

import (
	"testing"
	"time"
)

func TestTheDeadTunnelTimeoutIsHeldToWhatTheSocketOptionCanHold(t *testing.T) {
	for _, tc := range []struct {
		d  time.Duration
		ok bool
	}{
		{0, true},
		{time.Second, true},
		{45 * time.Second, true},
		{maxTunnelDeadTimeout, true},
		{-time.Second, false},
		{500 * time.Millisecond, false},
		{maxTunnelDeadTimeout + time.Millisecond, false},
		{50 * 24 * time.Hour, false},
	} {
		if err := checkTunnelDeadTimeout(tc.d); (err == nil) != tc.ok {
			t.Errorf("%s: error %v, want ok=%v", tc.d, err, tc.ok)
		}
	}
}
