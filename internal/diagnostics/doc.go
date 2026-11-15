// Package diagnostics holds what an operator turns on to investigate the
// proxy: the latency recorder (StartLatency, ObserveConn, ObserveRelated,
// ObserveQueue, FlowOf), which keeps a ring of recent measurements of
// selected sockets, the other side of their relays, the queues in front of
// them and what their owners report of them, and saves the part around an
// incident, and file-only profiling in builds with -tags profiling (Start).
package diagnostics
