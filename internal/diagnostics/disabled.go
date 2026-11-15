//go:build !profiling

package diagnostics

// Start is a no-op in release builds.
func Start() func() { return func() {} }
