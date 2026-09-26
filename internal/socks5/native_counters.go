package socks5

import "sync/atomic"

// NativeCounters says where the datagrams of 0x84 associations went, for the
// server's metrics: the probes say whether the path works, these what the
// datagrams actually took (finding 4 of the 2.3.0-rc1 audit's priorities,
// docs/reports/v2.3-rc1-audit-2026-09-26.md). Every field is a fixed label.
type NativeCounters struct {
	// Answers to the client: native, or by TCP because they are too big for
	// native, because the answers are on TCP, or because the native write
	// failed.
	AnswersNative, AnswersOversize, AnswersRoute, AnswersFailed atomic.Uint64
	// Datagrams of the client: native, or by TCP too big for native, or by
	// TCP otherwise (unverified, deaf or told).
	ClientNative, ClientOversize, ClientRoute atomic.Uint64
	// Moves of the answers between the paths, and words of the client that
	// came too late to move them (answerPath).
	ToNative, ToTCP, StaleLoss, StaleHeard atomic.Uint64
	// Frames the stream could not take in time (TunnelWriter).
	Drops TunnelDrops
}

// TunnelDrops counts the frames a TunnelWriter did not write: past its queue,
// or older than tunnelFrameAge when their turn came.
type TunnelDrops struct {
	Queue, Age atomic.Uint64
}
