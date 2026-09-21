package socks5

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestDatagramDNSIsCoalescedCachedAndDoesNotBlockIP(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var lookups atomic.Int32
		sent := make(chan string, 20)
		d := newUDPDispatcher(context.Background(), func(ctx context.Context, name string) (net.IP, error) {
			lookups.Add(1)
			select {
			case <-release:
				return net.IPv4(127, 0, 0, 1), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, func(p []byte, _ *net.UDPAddr) bool { sent <- string(p); return true }, func() {})
		defer d.close()
		addr := &AddrSpec{FQDN: "slow.example", Port: 53}
		for i := range 10 {
			if !d.submit(addr, []byte(fmt.Sprint(i))) {
				t.Fatal("unexpected drop")
			}
		}
		if !d.submit(&AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 53}, []byte("ip")) {
			t.Fatal("IP drop")
		}
		synctest.Wait()
		select {
		case got := <-sent:
			if got != "ip" {
				t.Fatalf("first: %q", got)
			}
		default:
			t.Fatal("DNS blocked IP")
		}
		if got := lookups.Load(); got != 1 {
			t.Fatalf("lookups for one pending name: %d", got)
		}
		close(release)
		synctest.Wait()
		for i := range 10 {
			if got := <-sent; got != fmt.Sprint(i) {
				t.Fatalf("packet %d: %q", i, got)
			}
		}
		d.submit(addr, []byte("cached"))
		synctest.Wait()
		if got := <-sent; got != "cached" {
			t.Fatal(got)
		}
		if lookups.Load() != 1 {
			t.Fatal("cached name resolved again")
		}
		time.Sleep(udpDNSReuse + time.Second)
		d.submit(addr, []byte("expired"))
		synctest.Wait()
		if got := <-sent; got != "expired" {
			t.Fatal(got)
		}
		if lookups.Load() != 2 {
			t.Fatal("expired name not resolved again")
		}
	})
}

func TestDatagramDNSQueueAndConcurrencyAreBoundedAndCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active, peak atomic.Int32
		flushed := false
		d := newUDPDispatcher(context.Background(), func(ctx context.Context, name string) (net.IP, error) {
			n := active.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			defer active.Add(-1)
			<-ctx.Done()
			return nil, ctx.Err()
		}, func([]byte, *net.UDPAddr) bool { t.Error("unresolved datagram delivered"); return false }, func() { flushed = true })
		for i := range 1000 {
			d.submit(&AddrSpec{FQDN: fmt.Sprintf("name%d", i%10), Port: 53}, []byte("payload"))
		}
		synctest.Wait()
		if peak.Load() > udpDNSWorkers || peak.Load() == 0 {
			t.Fatalf("peak resolvers: %d", peak.Load())
		}
		for range 1000 {
			d.submit(&AddrSpec{FQDN: "name0", Port: 53}, []byte("payload"))
		}
		synctest.Wait()
		if len(d.slots) > udpPendingLimit {
			t.Fatal("unbounded queue")
		}
		if d.submit(&AddrSpec{FQDN: "name0", Port: 53}, []byte("full")) {
			t.Fatal("full queue accepted packet")
		}
		d.close()
		if active.Load() != 0 || len(d.slots) != 0 || !flushed {
			t.Fatalf("unfinished cleanup: active=%d pending=%d flushed=%v", active.Load(), len(d.slots), flushed)
		}
	})
}

func TestDatagramSendFailureReleasesPendingBuffers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls := 0
		d := newUDPDispatcher(context.Background(), func(ctx context.Context, _ string) (net.IP, error) {
			select {
			case <-release:
				return net.IPv4(127, 0, 0, 1), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, func([]byte, *net.UDPAddr) bool { calls++; return false }, func() {})
		for range 20 {
			d.submit(&AddrSpec{FQDN: "one.example", Port: 53}, []byte("payload"))
		}
		synctest.Wait()
		close(release)
		synctest.Wait()
		d.close()
		if calls != 1 || len(d.slots) != 0 {
			t.Fatalf("calls=%d pending=%d", calls, len(d.slots))
		}
	})
}

func TestFullDNSQueueDoesNotDropIPDatagrams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sent := 0
		d := newUDPDispatcher(context.Background(), func(ctx context.Context, _ string) (net.IP, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, func(p []byte, _ *net.UDPAddr) bool {
			if string(p) != "ip" {
				t.Error("unresolved name delivered")
			}
			sent++
			return true
		}, func() {})
		defer d.close()
		for range udpPendingLimit {
			if !d.submit(&AddrSpec{FQDN: "blocked.example", Port: 53}, []byte("dns")) {
				t.Fatal("early queue drop")
			}
		}
		synctest.Wait()
		for range 100 {
			if !d.submit(&AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 53}, []byte("ip")) {
				t.Fatal("DNS queue dropped IP packet")
			}
		}
		if sent != 100 {
			t.Fatalf("delivered %d IP packets", sent)
		}
	})
}
