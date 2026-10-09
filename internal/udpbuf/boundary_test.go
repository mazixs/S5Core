package udpbuf

import (
	"net"
	"testing"
)

func TestInvalidSocketRequestsReturnErrorsWithoutLiveSockets(t *testing.T) {
	if c, err := ListenUnicast("invalid-network", &net.UDPAddr{}); err == nil || c != nil {
		t.Fatal("invalid relay socket accepted")
	}
	if c, err := DialUDP("invalid-network", nil, &net.UDPAddr{}); err == nil || c != nil {
		t.Fatal("invalid dial accepted")
	}
}
