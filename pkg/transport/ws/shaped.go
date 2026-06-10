package ws

import (
	"math/rand"
	"sync"
	"time"
)

// ShapedConn wraps a ws.Conn and splits large writes into multiple WebSocket
// frames of random sizes. This destroys fixed-size patterns (e.g. obfs frame
// headers) at the WebSocket layer, making traffic harder to fingerprint.
type ShapedConn struct {
	*Conn
	minFrame  int
	maxFrame  int
	maxJitter time.Duration
	rng       *rand.Rand
	writeMu   sync.Mutex
}

// NewShapedConn creates a traffic-shaped wrapper.
// minFrame and maxFrame define the random WS frame payload sizes.
// maxJitter adds a random delay (0–maxJitter) before each frame with 10% probability.
func NewShapedConn(c *Conn, minFrame, maxFrame int, maxJitter time.Duration) *ShapedConn {
	if minFrame <= 0 {
		minFrame = 1024
	}
	if maxFrame < minFrame {
		maxFrame = minFrame * 4
	}
	return &ShapedConn{
		Conn:      c,
		minFrame:  minFrame,
		maxFrame:  maxFrame,
		maxJitter: maxJitter,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Write sends the buffer as one or more WS binary frames.
// Fast path: if the payload fits in a single frame it is sent unchanged.
// Large payloads are split into random-sized frames to destroy fixed-size
// patterns (e.g. obfs headers) at the WebSocket layer.
func (c *ShapedConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Fast path: fits in a single frame — no splitting overhead.
	if len(b) <= c.maxFrame {
		if c.maxJitter > 0 && c.rng.Float32() < 0.1 {
			time.Sleep(time.Duration(c.rng.Int63n(int64(c.maxJitter))))
		}
		return c.Conn.Write(b)
	}

	total := 0
	for len(b) > 0 {
		frameSize := c.minFrame + c.rng.Intn(c.maxFrame-c.minFrame+1)
		if frameSize > len(b) {
			frameSize = len(b)
		}
		if c.maxJitter > 0 && c.rng.Float32() < 0.1 {
			time.Sleep(time.Duration(c.rng.Int63n(int64(c.maxJitter))))
		}
		n, err := c.Conn.Write(b[:frameSize])
		total += n
		if err != nil {
			return total, err
		}
		b = b[n:]
	}
	return total, nil
}
