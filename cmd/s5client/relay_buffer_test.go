package main

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"testing"
)

type onlyReader struct{ io.Reader }

// Each tunnel direction used to allocate its own 32 KiB copy buffer, because
// io.Copy handed the copy to TCPConn.ReadFrom, which has nothing to splice to
// and falls back to io.Copy with a fresh buffer. The pool makes a relay cost
// its two interface wrappers, not a buffer.
func TestTheTunnelRelayReusesItsBuffer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	dst, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	payload := make([]byte, 1024)
	run := func() { relayCopy(dst, onlyReader{bytes.NewReader(payload)}) }
	run()

	const rounds = 100
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		run()
	}
	runtime.ReadMemStats(&after)
	// Under -race sync.Pool drops a quarter of its Puts on purpose, so a
	// working pool averages about 8 KiB there and nothing without it; a fresh
	// buffer per copy is 32 KiB either way.
	if perCopy := (after.TotalAlloc - before.TotalAlloc) / rounds; perCopy > 16*1024 {
		t.Errorf("a relay direction allocates %d bytes; the copy buffer should come from the pool", perCopy)
	}
}
