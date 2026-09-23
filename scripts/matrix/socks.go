package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

func socksGreet(c net.Conn) error {
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var r [2]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return err
	}
	if r[0] != 5 || r[1] != 0 {
		return fmt.Errorf("socks greeting refused: %v", r)
	}
	return nil
}

func appendAddr(b []byte, host string, port int) []byte {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		b = append(b, 1)
		b = append(b, ip.To4()...)
	} else if ip != nil {
		b = append(b, 4)
		b = append(b, ip.To16()...)
	} else {
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

func readReply(c net.Conn) (*net.UDPAddr, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, err
	}
	if h[0] != 5 || h[1] != 0 {
		return nil, fmt.Errorf("socks reply %d", h[1])
	}
	var ip net.IP
	switch h[3] {
	case 1:
		ip = make(net.IP, 4)
	case 4:
		ip = make(net.IP, 16)
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(c, make([]byte, n[0])); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("socks atyp %d", h[3])
	}
	if ip != nil {
		if _, err := io.ReadFull(c, ip); err != nil {
			return nil, err
		}
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(p[:]))}, nil
}

// dialer returns a TCP dial function: direct when socks is empty.
func dialer(socks string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	if socks == "" {
		return d.DialContext
	}
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, "tcp", socks)
		if err != nil {
			return nil, err
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
		defer stop()
		host, ps, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(ps)
		if err := socksGreet(c); err != nil {
			_ = c.Close()
			return nil, err
		}
		if _, err := c.Write(appendAddr([]byte{5, 1, 0}, host, port)); err != nil {
			_ = c.Close()
			return nil, err
		}
		if _, err := readReply(c); err != nil {
			_ = c.Close()
			return nil, err
		}
		if !stop() {
			_ = c.Close()
			return nil, ctx.Err()
		}
		_ = c.SetDeadline(time.Time{})
		return c, nil
	}
}

// socksPacketConn is a SOCKS5 UDP association seen as a net.PacketConn.
// It deliberately has no SyscallConn: quic-go would read the socket itself.
type socksPacketConn struct {
	udp   *net.UDPConn
	relay *net.UDPAddr
	ctl   net.Conn
	rbuf  []byte
	wmu   sync.Mutex
	wbuf  []byte
}

// listenPacket binds to loopback only behind a SOCKS relay: a direct socket on
// 127.0.0.1 cannot reach a remote origin, and the kernel drops what it sends.
func listenPacket(ctx context.Context, socks string) (net.PacketConn, error) {
	bind := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if socks == "" {
		bind = nil
	}
	udp, err := net.ListenUDP("udp", bind)
	if err != nil {
		return nil, err
	}
	_ = udp.SetReadBuffer(4 << 20)
	_ = udp.SetWriteBuffer(4 << 20)
	if socks == "" {
		return udp, nil
	}
	var d net.Dialer
	ctl, err := d.DialContext(ctx, "tcp", socks)
	if err != nil {
		_ = udp.Close()
		return nil, err
	}
	fail := func(err error) (net.PacketConn, error) { _ = ctl.Close(); _ = udp.Close(); return nil, err }
	if dl, ok := ctx.Deadline(); ok {
		_ = ctl.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = ctl.SetDeadline(time.Now()) })
	defer stop()
	if err := socksGreet(ctl); err != nil {
		return fail(err)
	}
	if _, err := ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	relay, err := readReply(ctl)
	if err != nil {
		return fail(err)
	}
	if !stop() {
		return fail(ctx.Err())
	}
	_ = ctl.SetDeadline(time.Time{})
	if relay.IP == nil || relay.IP.IsUnspecified() {
		h, _, _ := net.SplitHostPort(socks)
		relay.IP = net.ParseIP(h)
	}
	return &socksPacketConn{udp: udp, relay: relay, ctl: ctl, rbuf: make([]byte, 65535), wbuf: make([]byte, 0, 65535)}, nil
}

func (p *socksPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("not a UDP address")
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	buf := appendAddr(append(p.wbuf[:0], 0, 0, 0), ua.IP.String(), ua.Port)
	buf = append(buf, b...)
	p.wbuf = buf[:0]
	if _, err := p.udp.WriteToUDP(buf, p.relay); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, _, err := p.udp.ReadFromUDP(p.rbuf)
		if err != nil {
			return 0, nil, err
		}
		d := p.rbuf[:n]
		if len(d) < 10 || d[2] != 0 {
			continue
		}
		var src *net.UDPAddr
		switch d[3] {
		case 1:
			src = &net.UDPAddr{IP: net.IP(append([]byte(nil), d[4:8]...)), Port: int(binary.BigEndian.Uint16(d[8:10]))}
			d = d[10:]
		case 4:
			if len(d) < 22 {
				continue
			}
			src = &net.UDPAddr{IP: net.IP(append([]byte(nil), d[4:20]...)), Port: int(binary.BigEndian.Uint16(d[20:22]))}
			d = d[22:]
		default:
			continue
		}
		return copy(b, d), src, nil
	}
}

func (p *socksPacketConn) Close() error {
	_ = p.ctl.Close()
	return p.udp.Close()
}

func (p *socksPacketConn) LocalAddr() net.Addr                { return p.udp.LocalAddr() }
func (p *socksPacketConn) SetDeadline(t time.Time) error      { return p.udp.SetDeadline(t) }
func (p *socksPacketConn) SetReadDeadline(t time.Time) error  { return p.udp.SetReadDeadline(t) }
func (p *socksPacketConn) SetWriteDeadline(t time.Time) error { return p.udp.SetWriteDeadline(t) }
func (p *socksPacketConn) SetReadBuffer(n int) error          { return p.udp.SetReadBuffer(n) }
func (p *socksPacketConn) SetWriteBuffer(n int) error         { return p.udp.SetWriteBuffer(n) }
