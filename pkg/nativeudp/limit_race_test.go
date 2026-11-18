package nativeudp

import (
	"errors"
	"testing"
)

func TestALimitChangeBetweenSizingAndSendDoesNotInvalidateTheSession(t *testing.T) {
	client, _ := pair(t)
	client.ApplyProbeLimit(ExtendedProbe{Generation: 1, Limit: MaxWire})
	payload := make([]byte, client.MaxPayload())
	done := make(chan struct{})
	go func() { client.ApplyProbeLimit(ExtendedProbe{Generation: 2, Limit: BaseWire}); close(done) }()
	<-done
	if _, err := client.Seal(nil, KindData, payload); err != ErrPacket { //nolint:errorlint // v2.3.0 callers compare the exact sentinel.
		t.Fatalf("legacy Seal: %v, want ErrPacket", err)
	}
	write := func([]byte) error { t.Fatal("oversized packet reached write"); return nil }
	if err := client.SealWrite(KindData, payload, write); err != ErrPacket { //nolint:errorlint // v2.3.0 callers compare the exact sentinel.
		t.Fatalf("legacy SealWrite: %v, want ErrPacket", err)
	}
	if err := client.SealWriteWithLimitError(KindData, payload, write); !errors.Is(err, ErrPayloadTooLarge) || errors.Is(err, ErrPacket) {
		t.Fatalf("SealWriteWithLimitError: %v, want ErrPayloadTooLarge", err)
	}
	if _, err := client.SealWithLimitError(nil, KindData, payload); !errors.Is(err, ErrPayloadTooLarge) || errors.Is(err, ErrPacket) {
		t.Fatalf("limit race classified as %v", err)
	}
	if _, err := client.SealWithLimitError(nil, KindData, []byte("still usable")); err != nil {
		t.Fatal("short datagram cannot use the surviving session", err)
	}
}
