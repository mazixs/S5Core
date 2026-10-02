package s5server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/mazixs/S5Core/internal/socks5"
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
func (a *nativeAssociation) MaxPayload() int { return a.session.MaxPayload() }

func (a *nativeAssociation) Send(data []byte) error {
	return nativeSendError(a.hub.Send(a.session, nativeudp.KindData, data))
}

// nativeSendError tells the relay which failures end the path. The hub answers
// ErrPacket for a removed session and for one with no peer yet (an oversized
// payload is never passed), and a closed socket carries nothing again; any
// other error is one lost write.
func nativeSendError(err error) error {
	if err != nil && (errors.Is(err, nativeudp.ErrPacket) || errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("%w: %w", socks5.ErrNativePathGone, err)
	}
	return err
}

func (a *nativeAssociation) Close()             { a.hub.Remove(a.session) }
func (a *nativeAssociation) Resync(next uint64) { a.hub.Resync(a.session, next) }
func (a *nativeAssociation) Next() uint64       { return a.session.Next() }
func (a *nativeAssociation) Receive(ctx context.Context, datagram func(uint64, []byte), heard func(uint64)) bool {
	select {
	case <-ctx.Done():
		return false
	case <-a.session.Heard():
		heard(a.session.HeardCounter())
		return true
	case packet := <-a.session.Packets():
		datagram(packet.Counter, packet.Data)
		packet.Release()
		return true
	}
}

func registerNativeMetrics(t *Telemetry, hub *nativeudp.Hub, c *socks5.NativeCounters) (metric.Registration, error) {
	if t == nil {
		return nil, nil
	}
	datagrams := []struct {
		direction, path string
		count           *atomic.Uint64
	}{
		{"to_client", "native", &c.AnswersNative}, {"to_client", "tcp_oversize", &c.AnswersOversize},
		{"to_client", "tcp_route", &c.AnswersRoute}, {"to_client", "tcp_failed", &c.AnswersFailed},
		{"from_client", "native", &c.ClientNative}, {"from_client", "tcp_oversize", &c.ClientOversize},
		{"from_client", "tcp_route", &c.ClientRoute},
	}
	events := []struct {
		event string
		count *atomic.Uint64
	}{
		{"to_native", &c.ToNative}, {"to_tcp", &c.ToTCP},
		{"stale_loss", &c.StaleLoss}, {"stale_heard", &c.StaleHeard},
	}
	drops := []struct {
		reason string
		count  *atomic.Uint64
	}{
		{"queue", &c.Drops.Queue}, {"age", &c.Drops.Age},
	}
	return t.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		st := hub.Stats()
		for _, row := range []struct {
			outcome string
			count   uint64
		}{
			{"accepted", st.Accepted}, {"tag", st.TagDrops},
			{"replay", st.ReplayDrops}, {"auth", st.AuthDrops},
			{"read_error", st.ReadErrors},
		} {
			o.ObserveInt64(t.NativeUDPPackets, int64(row.count), metric.WithAttributes(attribute.String("outcome", row.outcome)))
		}
		o.ObserveInt64(t.NativeUDPSessions, int64(st.Active))
		for _, row := range datagrams {
			o.ObserveInt64(t.NativeUDPDatagrams, int64(row.count.Load()), metric.WithAttributes(
				attribute.String("direction", row.direction), attribute.String("path", row.path)))
		}
		for _, row := range events {
			o.ObserveInt64(t.NativeUDPRouteEvents, int64(row.count.Load()), metric.WithAttributes(attribute.String("event", row.event)))
		}
		for _, row := range drops {
			o.ObserveInt64(t.NativeUDPStreamDrops, int64(row.count.Load()), metric.WithAttributes(attribute.String("reason", row.reason)))
		}
		return nil
	}, t.NativeUDPPackets, t.NativeUDPSessions, t.NativeUDPDatagrams, t.NativeUDPRouteEvents, t.NativeUDPStreamDrops)
}
