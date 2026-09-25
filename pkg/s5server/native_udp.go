package s5server

import (
	"context"

	"github.com/mazixs/S5Core/pkg/nativeudp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// nativeAssociation is the bridge between transport keys and the SOCKS5
// datagram relay. The SOCKS5 package only sees an authenticated packet pipe.
type nativeAssociation struct {
	hub     *nativeudp.Hub
	session *nativeudp.Session
}

func (a *nativeAssociation) Port() int       { return a.hub.Port() }
func (a *nativeAssociation) MaxPayload() int { return nativeudp.MaxWire - 8 - 2 - 16 }
func (a *nativeAssociation) Send(data []byte) error {
	return a.hub.Send(a.session, nativeudp.KindData, data)
}
func (a *nativeAssociation) Close() { a.hub.Remove(a.session) }
func (a *nativeAssociation) Receive(ctx context.Context) ([]byte, bool) {
	select {
	case <-ctx.Done():
		return nil, false
	case packet := <-a.session.Packets():
		return packet.Data, true
	}
}

func registerNativeMetrics(t *Telemetry, hub *nativeudp.Hub) (metric.Registration, error) {
	if t == nil {
		return nil, nil
	}
	return t.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		st := hub.Stats()
		for _, row := range []struct {
			outcome string
			count   uint64
		}{
			{"accepted", st.Accepted}, {"tag", st.TagDrops},
			{"replay", st.ReplayDrops}, {"auth", st.AuthDrops},
		} {
			o.ObserveInt64(t.NativeUDPPackets, int64(row.count), metric.WithAttributes(attribute.String("outcome", row.outcome)))
		}
		o.ObserveInt64(t.NativeUDPSessions, int64(st.Active))
		return nil
	}, t.NativeUDPPackets, t.NativeUDPSessions)
}
