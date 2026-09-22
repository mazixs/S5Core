package main

import (
	"fmt"
	"testing"
)

func BenchmarkRouteDomains(b *testing.B) {
	for _, n := range []int{0, 10, 1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			patterns := make([]string, n)
			for i := range patterns {
				patterns[i] = fmt.Sprintf("*.site%d.example", i)
			}
			matcher := newDomainMatcher(patterns)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_ = matcher.Match("unlisted.example")
			}
		})
	}
}
