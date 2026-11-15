// Package diagnostics holds what an operator turns on to investigate the
// proxy: the latency recorder (StartLatency, ObserveConn), which keeps a ring
// of recent measurements of selected sockets and saves the part around an
// incident, and file-only profiling in builds with -tags profiling (Start).
package diagnostics
