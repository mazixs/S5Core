package obfs

import (
	"testing"
)

func TestReplayWindow(t *testing.T) {
	rw := newReplayWindow(4)

	nonce1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	nonce2 := []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

	if !rw.checkAndAdd(nonce1) {
		t.Fatal("first nonce should be accepted")
	}
	if !rw.checkAndAdd(nonce2) {
		t.Fatal("second nonce should be accepted")
	}
	if rw.checkAndAdd(nonce1) {
		t.Fatal("duplicate nonce should be rejected")
	}

	// Fill the window
	nonce3 := []byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	nonce4 := []byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	if !rw.checkAndAdd(nonce3) {
		t.Fatal("third nonce should be accepted")
	}
	if !rw.checkAndAdd(nonce4) {
		t.Fatal("fourth nonce should be accepted")
	}

	// nonce1 is the oldest and about to be evicted — re-adding it is allowed
	if !rw.checkAndAdd(nonce1) {
		t.Fatal("oldest nonce about to be evicted should be accepted again")
	}
}

func TestReplayWindowNil(t *testing.T) {
	var rw *replayWindow
	if !rw.checkAndAdd([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
		t.Fatal("nil window should accept everything")
	}
}
