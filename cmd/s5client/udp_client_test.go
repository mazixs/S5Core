package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestUDPAddrAtomicPointer(t *testing.T) {
	var ptr atomic.Pointer[net.UDPAddr]

	// Concurrent stores
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: port,
			}
			ptr.Store(addr)
		}(i)
	}

	// Concurrent loads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ptr.Load()
		}()
	}

	wg.Wait()

	addr := ptr.Load()
	if addr == nil {
		t.Fatal("expected non-nil address")
	}
	if addr.IP == nil {
		t.Fatal("expected non-nil IP")
	}
}
