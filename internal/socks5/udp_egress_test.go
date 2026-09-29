package socks5

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestARotatingSocketOpensAndCloses(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	c := e.current()
	if c == nil {
		t.Fatal("no socket")
	}
	if c.LocalAddr().(*net.UDPAddr).Port == 0 {
		t.Fatal("socket has no port")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Rotation only arms when nothing has answered, enough has been sent, and the
// socket has been open long enough.
func TestTheRotationGate(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	now := time.Now()
	e.openedAt.Store(now.Add(-2 * time.Second).UnixNano())

	if e.deadLongEnough(now, udpRotateMinTx, udpRotateWindow) {
		t.Fatal("armed with nothing sent")
	}
	e.sentToTarget()
	if e.deadLongEnough(now, udpRotateMinTx, udpRotateWindow) {
		t.Fatal("armed below the minimum sent")
	}
	e.sentToTarget()
	if !e.deadLongEnough(now, udpRotateMinTx, udpRotateWindow) {
		t.Fatal("did not arm although dead")
	}
	// A single reply disarms it for good.
	e.gotReply()
	if e.deadLongEnough(now, udpRotateMinTx, udpRotateWindow) {
		t.Fatal("still armed after a reply")
	}
}

// A socket freshly open has not been dead long enough yet.
func TestAFreshSocketDoesNotRotate(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.sentToTarget()
	e.sentToTarget()
	if e.deadLongEnough(time.Now(), udpRotateMinTx, udpRotateWindow) {
		t.Fatal("armed within the window")
	}
}

// rotate replaces the socket with a new one, counts the rotation, resets the
// sent count and closes the old socket; replaced tells the old socket from the
// current one.
func TestRotateReplacesTheSocket(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	old := e.current()
	e.sentToTarget()
	e.sentToTarget()

	ok, err := e.rotate()
	if err != nil || !ok {
		t.Fatalf("rotate: ok=%v err=%v", ok, err)
	}
	now := e.current()
	if now == old {
		t.Fatal("socket was not replaced")
	}
	if e.rotations() != 1 {
		t.Fatalf("rotations %d, want 1", e.rotations())
	}
	if e.tx.Load() != 0 {
		t.Fatalf("sent count %d, want 0 after rotation", e.tx.Load())
	}
	if !e.replaced(old) {
		t.Fatal("replaced should see the old socket as replaced")
	}
	if e.replaced(now) {
		t.Fatal("replaced should not see the current socket as replaced")
	}
	// The old socket is closed: a read returns at once with an error.
	_ = old.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := old.ReadFromUDPAddrPort(make([]byte, 1)); err == nil {
		t.Fatal("old socket was left open")
	}
}

// Only the first reply is reported as such, so the reader logs a revival once.
func TestOnlyTheFirstReplyIsTheFirst(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if !e.gotReply() {
		t.Fatal("the first reply was not reported as the first")
	}
	if e.gotReply() {
		t.Fatal("the second reply was reported as the first")
	}
	if e.recvCount() != 2 {
		t.Fatalf("replies %d, want 2", e.recvCount())
	}
}

// A closed association does not rotate, and replaced reports no rotation, so
// the reader takes the closed socket's error as the end it is.
func TestAClosedEgressDoesNotRotate(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	c := e.current()
	_ = e.Close()
	if ok, err := e.rotate(); ok || err != nil {
		t.Fatalf("rotate after close: ok=%v err=%v", ok, err)
	}
	if e.replaced(c) {
		t.Fatal("a closed association is not a rotation")
	}
}

// The watcher rotates a dead socket and stops once a reply comes.
func TestTheWatcherRotatesUntilAReplyComes(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// Pre-age the socket and mark it as sending, so the first tick arms.
	e.sentToTarget()
	e.sentToTarget()
	e.openedAt.Store(time.Now().Add(-2 * time.Second).UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var rotations atomic.Int64
	done := make(chan struct{})
	go func() {
		watchDeadEgress(ctx, e, func(int) {
			// Simulate a reply arriving on the fresh socket, which must stop
			// the watcher after this one rotation.
			rotations.Add(1)
			e.gotReply()
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not return")
	}
	if got := rotations.Load(); got != 1 {
		t.Fatalf("rotated %d times, want exactly 1 before the reply stopped it", got)
	}
	if e.rotations() != 1 {
		t.Fatalf("rotations %d, want 1", e.rotations())
	}
}

// A destination that never answers gets exactly udpRotateMax draws, no more.
func TestTheWatcherGivesUpAfterTheLastDraw(t *testing.T) {
	e, err := newRotatingUDP(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	arm := func() {
		e.sentToTarget()
		e.sentToTarget()
		e.openedAt.Store(time.Now().Add(-2 * time.Second).UnixNano())
	}
	arm()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var rotations atomic.Int64
	done := make(chan struct{})
	go func() {
		watchDeadEgress(ctx, e, func(int) {
			rotations.Add(1)
			// The application keeps retrying on the new socket, and it stays
			// as silent as the last.
			arm()
		})
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("watcher did not give up before the context ended")
	}
	if got := rotations.Load(); got != udpRotateMax {
		t.Fatalf("rotated %d times, want %d", got, udpRotateMax)
	}
	if e.rotations() != udpRotateMax {
		t.Fatalf("rotations %d, want %d", e.rotations(), udpRotateMax)
	}
}
