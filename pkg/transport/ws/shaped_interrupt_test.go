package ws

import (
	"errors"
	"math/rand"
	"os"
	"testing"
	"testing/synctest"
	"time"
)

// A short payload uses one frame. Seed 9 chooses a 1.206120304s pause
// before that frame; virtual time makes the lifecycle assertions exact.
const testShapingPause = 1206120304 * time.Nanosecond

func jitterConn(t *testing.T) (*ShapedConn, <-chan struct{}) {
	t.Helper()
	base, writes := blockedPeer(t)
	c := NewShapedConn(base, DefaultMinFrame, DefaultMaxFrame, 10*time.Second)
	c.rng = rand.New(rand.NewSource(9))
	return c, writes
}

func TestShapedCloseInterruptsJitter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _ := jitterConn(t)
		done := make(chan error, 1)
		go func() { _, err := c.Write([]byte("first")); done <- err }()
		synctest.Wait()
		start := time.Now()
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("write to closed connection succeeded")
			}
		default:
			t.Error("Close left a writer waiting for jitter")
			time.Sleep(testShapingPause)
			<-done
			return
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("Close took %s of virtual time", elapsed)
		}
	})
}

// Mutex waits are not durably blocked in synctest. Exercise concurrent
// writers outside the bubble and use the timeout only as a hang watchdog.
func TestShapedCloseReleasesConcurrentWriters(t *testing.T) {
	c, _ := jitterConn(t)
	done := make(chan error, 32)
	ready := make(chan struct{}, cap(done))
	for range cap(done) {
		go func() {
			ready <- struct{}{}
			_, err := c.Write([]byte("payload"))
			done <- err
		}()
	}
	for range cap(done) {
		<-ready
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	watchdog := time.NewTimer(2 * time.Second)
	defer watchdog.Stop()
	for range cap(done) {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("write to silent, closed peer succeeded")
			}
		case <-watchdog.C:
			t.Fatal("Close left concurrent writers blocked")
		}
	}
}

func TestShapedWriteDeadlineInterruptsJitter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, writes := jitterConn(t)
		done := make(chan error, 1)
		go func() { _, err := c.Write([]byte("payload")); done <- err }()
		synctest.Wait()
		if err := c.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("write error = %v, want deadline exceeded", err)
			}
		default:
			t.Error("deadline left Write waiting for jitter")
			_ = c.Close()
			time.Sleep(testShapingPause)
			<-done
			return
		}
		select {
		case <-writes:
			t.Fatal("expired write reached the socket")
		default:
		}
	})
}

func TestShapedDeadlineExtensionAndClearPreservePause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, writes := jitterConn(t)
		if err := c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := c.Write([]byte("payload")); done <- err }()
		synctest.Wait()
		time.Sleep(50 * time.Millisecond)
		if err := c.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
		if err := c.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("old deadline interrupted write: %v", err)
		default:
		}
		select {
		case <-writes:
			t.Fatal("updating deadline skipped the remaining jitter")
		default:
		}
		time.Sleep(testShapingPause - 150*time.Millisecond)
		synctest.Wait()
		select {
		case <-writes:
		default:
			t.Fatal("updating deadline restarted jitter instead of preserving it")
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err == nil {
			t.Fatal("blocked socket write succeeded")
		}
	})
}
