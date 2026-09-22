package ws

import (
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit capacity check; skipped by CI. Includes both ends' user-space
// memory. Kernel socket memory is not part of RSS and must be budgeted apart.
func TestPerformanceIdleConnections(t *testing.T) {
	count, e := strconv.Atoi(os.Getenv("S5_WS_IDLE"))
	if e != nil || count < 1 {
		t.Skip("set S5_WS_IDLE=1000 or 10000")
	}
	up := NewUpgrader(UpgraderOpts{Path: "/ws"})
	accepted := make(chan *Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := up.Upgrade(w, r)
		if e == nil {
			accepted <- c
		}
	}))
	defer srv.Close()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var held []*Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	for i := 0; i < count; i++ {
		c, e := Dial(DialOpts{URL: strings.Replace(srv.URL, "http:", "ws:", 1) + "/ws"})
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, c)
		select {
		case c := <-accepted:
			held = append(held, c)
		case <-time.After(time.Second):
			t.Fatal("upgrade did not complete")
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	data, e := os.ReadFile("/proc/self/status")
	if e != nil {
		t.Fatal(e)
	}
	var rss string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			rss = line
		}
	}
	t.Logf("connections=%d heap_delta=%d heap_per_pair=%d %s", count, after.HeapAlloc-before.HeapAlloc, (after.HeapAlloc-before.HeapAlloc)/uint64(count), rss)
	runtime.KeepAlive(held)
}
