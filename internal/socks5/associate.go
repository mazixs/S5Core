package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// udpPacket is used to pass packets between sockets
type udpPacket struct {
	addr *net.UDPAddr
	data []byte
}

// handleAssociate implements the standard RFC 1928 UDP ASSOCIATE.
// The client connects via TCP to request a UDP relay.
// The server opens a UDP socket and tells the client its IP/Port.
// The client then sends UDP packets to that socket.
func (s *Server) handleAssociate(ctx context.Context, conn conn, req *Request) error {
	if _, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("associate to %v blocked by rules", req.DestAddr)
	}

	// Bind to a local UDP port
	bindAddr := &net.UDPAddr{IP: s.config.BindIP, Port: 0}
	if bindAddr.IP == nil {
		bindAddr.IP = net.IPv4zero
	}
	udpConn, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("failed to bind UDP port: %v", err)
	}
	defer udpConn.Close()

	// Tell the client where to send UDP packets
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	bindSpec := AddrSpec{IP: localAddr.IP, Port: localAddr.Port}

	// Some clients expect our public IP if we bound to 0.0.0.0
	if bindSpec.IP.IsUnspecified() {
		if tcpLocal, ok := conn.(net.Conn).LocalAddr().(*net.TCPAddr); ok {
			bindSpec.IP = tcpLocal.IP
		}
	}

	if err := sendReply(conn, successReply, &bindSpec); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	// We multiplex the UDP stream
	// Client -> S5Core -> Target
	// Target -> S5Core -> Client

	// We only accept packets from the client's registered IP (weak security as per RFC)
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	clientUDPAddr := &net.UDPAddr{} // will be populated on first packet from client

	bufPool := sync.Pool{
		New: func() interface{} { return make([]byte, 65535) },
	}

	errCh := make(chan error, 2)
	clientToTarget := make(chan udpPacket, 32)
	targetToClient := make(chan udpPacket, 32)

	var wg sync.WaitGroup

	// TCP Connection monitor - if TCP closes, UDP tunnel dies
	wg.Add(1)
	go func() {
		defer wg.Done()
		var b [1]byte
		_, err := conn.(net.Conn).Read(b[:])
		errCh <- fmt.Errorf("tcp control connection closed: %v", err)
	}()

	// UDP Reader
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf := bufPool.Get().([]byte)
			n, rAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- fmt.Errorf("udp read failed: %w", err)
				return
			}

			// When testing locally, both client and target have IP 127.0.0.1.
			// We MUST use the explicit UDP port if we know it (after first packet),
			// otherwise we fall back to checking just IP (since SOCKS5 RFC says client IP
			// connects, but we don't know the client UDP port until the first packet).
			isFromClient := false
			if clientUDPAddr.IP != nil {
				// We already know the client's exact UDP IP:Port
				isFromClient = rAddr.String() == clientUDPAddr.String()
			} else {
				// First packet: we only know the client's IP from the TCP connection
				isFromClient = rAddr.IP.String() == clientIP
			}

			if isFromClient {
				// Packet from Client -> Target
				// Must have SOCKS5 UDP header
				hdrLen, dstAddr, err := ParseUDPHeader(buf[:n])
				if err != nil {
					s.config.Logger.Warn("socks: invalid UDP header from client", "error", err)
					bufPool.Put(buf)
					continue
				}

				var dAddr net.Addr
				if dstAddr.FQDN != "" {
					_, resolvedIP, err := s.config.Resolver.Resolve(ctx, dstAddr.FQDN)
					if err != nil {
						s.config.Logger.Warn("socks: udp fqdn resolve failed", "error", err)
						bufPool.Put(buf)
						continue
					}
					dAddr = &net.UDPAddr{IP: resolvedIP, Port: dstAddr.Port}
				} else {
					dAddr = &net.UDPAddr{IP: dstAddr.IP, Port: dstAddr.Port}
				}

				// Remember client's actual UDP ephemeral port
				clientUDPAddr = rAddr

				// Send raw payload to target
				payload := make([]byte, n-hdrLen)
				copy(payload, buf[hdrLen:n])
				clientToTarget <- udpPacket{addr: dAddr.(*net.UDPAddr), data: payload}
			} else {
				// Packet from Target -> Client
				// Needs SOCKS5 UDP header appended
				if clientUDPAddr.IP == nil {
					bufPool.Put(buf)
					continue // Drop if we don't know the client's UDP port yet
				}

				payload := make([]byte, n)
				copy(payload, buf[:n])

				srcSpec := &AddrSpec{IP: rAddr.IP, Port: rAddr.Port}
				packetData := BuildUDPHeader(srcSpec, payload)

				targetToClient <- udpPacket{addr: clientUDPAddr, data: packetData}
			}
			bufPool.Put(buf)
		}
	}()

	// UDP Writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt := <-clientToTarget:
				udpConn.WriteToUDP(pkt.data, pkt.addr)
			case pkt := <-targetToClient:
				udpConn.WriteToUDP(pkt.data, pkt.addr)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for any critical failure
	err = <-errCh

	// Cancel and cleanup happens via defers and TCP close
	return nil
}

// handleUDPTcpmux implements a custom reliable UDP-over-TCP tunnel (Command 0x83).
// This prevents STUN/WebRTC leaks bypassing the obfuscated TCP tunnel.
// The client multiplexes UDP packets into the TCP stream using a simple framing:
// [Length Uint16] [SOCKS5 UDP Header] [Payload]
func (s *Server) handleUDPTcpmux(ctx context.Context, conn conn, req *Request) error {
	if _, ok := s.config.Rules.Allow(ctx, req); !ok {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("udp-tcpmux to %v blocked by rules", req.DestAddr)
	}

	// We don't need to listen on an incoming UDP port because the client pushes UDP
	// traffic through this active TCP connection. We just need an unbound UDP
	// socket to send/receive to the actual targets on the internet.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		if err := sendReply(conn, serverFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("failed to bind local udp socket: %v", err)
	}
	defer udpConn.Close()

	// Reply success (BND.ADDR/PORT is irrelevant since traffic flows via TCP)
	bindSpec := AddrSpec{IP: net.IPv4zero, Port: 0}
	if err := sendReply(conn, successReply, &bindSpec); err != nil {
		return fmt.Errorf("failed to send reply: %v", err)
	}

	errCh := make(chan error, 2)
	tcpConn := conn.(net.Conn)
	tcpConn.SetDeadline(time.Time{}) // Disable timeouts, this is a long-lived tunnel

	// Go routine to read UDP packets from Internet and write to TCP stream
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- fmt.Errorf("udp socket read error: %w", err)
				return
			}

			// Wrap in SOCKS5 UDP Header representing the source
			srcSpec := &AddrSpec{IP: rAddr.IP, Port: rAddr.Port}
			socksHdr := BuildUDPHeader(srcSpec, buf[:n])

			// Prepend 16-bit length prefix for TCP framing
			frame := make([]byte, 2+len(socksHdr))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(socksHdr)))
			copy(frame[2:], socksHdr)

			if _, err := tcpConn.Write(frame); err != nil {
				errCh <- fmt.Errorf("tcp write error: %w", err)
				return
			}
		}
	}()

	// Read UDP packets from TCP stream and send to Internet
	go func() {
		lenBuf := make([]byte, 2)
		for {
			// Read 16-bit length
			if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
				errCh <- fmt.Errorf("tcp read length error: %w", err)
				return
			}

			packetLen := binary.BigEndian.Uint16(lenBuf)
			if packetLen == 0 {
				continue // Keep-alive
			}

			// Read inner SOCKS5 UDP Frame
			frameBuf := make([]byte, packetLen)
			if _, err := io.ReadFull(tcpConn, frameBuf); err != nil {
				errCh <- fmt.Errorf("tcp read frame error: %w", err)
				return
			}

			hdrLen, dstAddr, err := ParseUDPHeader(frameBuf)
			if err != nil {
				s.config.Logger.Warn("socks: invalid udp-tcpmux header", "error", err)
				continue
			}

			var dAddr net.Addr
			if dstAddr.FQDN != "" {
				_, resolvedIP, err := s.config.Resolver.Resolve(ctx, dstAddr.FQDN)
				if err != nil {
					s.config.Logger.Warn("socks: udp-tcpmux fqdn resolve failed", "error", err)
					continue
				}
				dAddr = &net.UDPAddr{IP: resolvedIP, Port: dstAddr.Port}
			} else {
				dAddr = &net.UDPAddr{IP: dstAddr.IP, Port: dstAddr.Port}
			}

			// Send to Internet
			payload := frameBuf[hdrLen:]
			if _, err := udpConn.WriteToUDP(payload, dAddr.(*net.UDPAddr)); err != nil {
				s.config.Logger.Warn("socks: udp-tcpmux write to internet failed", "error", err)
			}
		}
	}()

	return <-errCh // Block until either side errors
}
