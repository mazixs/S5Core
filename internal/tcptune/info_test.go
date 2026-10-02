package tcptune

import (
	"net"
	"testing"
)

func TestAConnectionWithoutASocketHasNoInfo(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if info, ok := InfoOf(a); ok {
		t.Fatalf("a pipe has TCP info: %+v", info)
	}
}
