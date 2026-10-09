package socks5

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestAllUDPDeliveryPathsRejectBroadcastAndSpecialDestinations(t *testing.T) {
	for _, path := range []string{"plain", "tunnel", "native"} {
		t.Run(path, func(t *testing.T) {
			var drops atomic.Int64
			conf := &Config{DenyPrivateDest: true, Logger: slog.New(slog.DiscardHandler), OnUDPDrop: func(reason string) {
				if reason == UDPDropPrivate {
					drops.Add(1)
				}
			}}
			var conn net.Conn
			var send func([]byte)
			if path == "native" {
				native := newScriptedNative()
				conf.NativeUDP = func(net.Conn) (NativeAssociation, error) { return native, nil }
				_, conn, _ = nativeRequest(t, conf)
				send = func(data []byte) { native.in <- scriptedDatagram{data: data} }
			} else {
				command := UDPTunnelCommand
				if path == "plain" {
					command = AssociateCommand
				}
				var reply []byte
				conn, reply = associateThrough(t, privateDestServer(t, conf), command, []byte{1, 0, 0, 0, 0, 0, 0})
				if path == "plain" {
					client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					proxy := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
					send = func(data []byte) {
						if _, err := client.WriteToUDP(data, proxy); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					send = func(data []byte) {
						frame := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
						if _, err := conn.Write(append(frame, data...)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			defer conn.Close()
			for _, ip := range []string{"255.255.255.255", "240.1.2.3", "168.63.129.16", "198.19.1.2"} {
				send(BuildUDPHeader(&AddrSpec{IP: net.ParseIP(ip), Port: 53}, []byte("denied")))
			}
			until := time.Now().Add(3 * time.Second)
			for drops.Load() < 4 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if drops.Load() != 4 {
				t.Fatalf("%s: private drops=%d, want 4", path, drops.Load())
			}
		})
	}
}
