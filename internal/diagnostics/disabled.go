//go:build !profiling

// Package diagnostics enables file-only profiling in explicit diagnostic builds.
package diagnostics

// Start is a no-op in release builds.
func Start() func() { return func() {} }
