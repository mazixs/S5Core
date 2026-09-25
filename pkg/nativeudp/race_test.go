//go:build race

package nativeudp

// The race detector drops a share of what goes back into a sync.Pool, so a
// pooled path allocates under it by design.
const raceEnabled = true
