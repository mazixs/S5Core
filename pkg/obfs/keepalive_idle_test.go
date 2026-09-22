package obfs

import (
	"bytes"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestKeepaliveSuppressionHonorsMaximum(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a, b := net.Pipe()
		defer b.Close()
		go io.Copy(io.Discard, b)
		log := &writeLog{Conn: a}
		c, e := NewClientConn(log, Config{PSK: bytes.Repeat([]byte("k"), 32), MTU: 1400, KeepaliveMin: 20 * time.Second, KeepaliveMax: 20 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		start := time.Now()
		if _, e := c.Write([]byte("initial")); e != nil {
			t.Fatal(e)
		}
		synctest.Wait()
		time.Sleep(time.Second)
		if _, e := c.Write([]byte("last application data")); e != nil {
			t.Fatal(e)
		}
		time.Sleep(30 * time.Second)
		synctest.Wait()
		_, times := log.snapshot()
		t.Logf("at=%s wire_writes=%d last_write_at=%s silence=%s configured_max=20s", time.Since(start), len(times), times[len(times)-1].Sub(start), time.Since(times[len(times)-1]))
		if len(times) != 3 || times[2].Sub(times[1]) != 20*time.Second {
			t.Fatal("keepalive did not honor maximum idle", times)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		_, times = log.snapshot()
		gap := times[len(times)-1].Sub(times[len(times)-2])
		t.Logf("next keepalive_at=%s previous_gap=%s", times[len(times)-1].Sub(start), gap)
		if gap > 20*time.Second {
			t.Fatal("keepalive exceeded maximum idle")
		}
	})
}

func TestDefaultKeepaliveMaximumAcrossApplicationOffsets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for trial := 0; trial < 64; trial++ {
			a, b := net.Pipe()
			go io.Copy(io.Discard, b)
			log := &writeLog{Conn: a}
			c, err := NewClientConn(log, Config{PSK: bytes.Repeat([]byte("k"), 32), MTU: 1400, KeepaliveMin: DefaultKeepaliveMin, KeepaliveMax: DefaultKeepaliveMax})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("initial")); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			time.Sleep(time.Duration(1+trial%19) * time.Second)
			if _, err := c.Write([]byte("application")); err != nil {
				t.Fatal(err)
			}
			time.Sleep(60 * time.Second)
			synctest.Wait()
			_, times := log.snapshot()
			for i := 1; i < len(times); i++ {
				if gap := times[i].Sub(times[i-1]); gap > DefaultKeepaliveMax {
					t.Fatalf("trial=%d gap=%v", trial, gap)
				}
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			_, before := log.snapshot()
			time.Sleep(time.Minute)
			synctest.Wait()
			_, after := log.snapshot()
			if len(before) != len(after) {
				t.Fatal("keepalive sent after CloseWrite")
			}
			c.Close()
			b.Close()
			synctest.Wait()
		}
	})
}
