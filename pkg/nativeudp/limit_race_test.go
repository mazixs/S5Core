package nativeudp

import (
	"errors"
	"testing"
)

func TestALimitChangeBetweenSizingAndSendDoesNotInvalidateTheSession(t *testing.T) {
	client, _ := pair(t)
	client.ApplyProbeLimit(Probe{Generation: 1, Limit: MaxWire})
	payload := make([]byte, client.MaxPayload())
	done := make(chan struct{})
	go func() { client.ApplyProbeLimit(Probe{Generation: 2, Limit: BaseWire}); close(done) }()
	<-done
	if _, err := client.Seal(nil, KindData, payload); !errors.Is(err, ErrPayloadTooLarge) || errors.Is(err, ErrPacket) {
		t.Fatalf("limit race classified as %v", err)
	}
	if _, err := client.Seal(nil, KindData, []byte("still usable")); err != nil {
		t.Fatal("short datagram cannot use the surviving session", err)
	}
}
