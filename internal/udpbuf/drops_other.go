//go:build !linux

package udpbuf

// ReceiveDrops has no count to read outside Linux.
func ReceiveDrops() (uint64, bool) { return 0, false }
