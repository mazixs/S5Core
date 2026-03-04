package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

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

	username := extractUsername(req)

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

	// We only accept packets from the client's registered IP (weak security as per RFC)
	clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// clientUDPAddr is accessed from multiple goroutines — use atomic pointer.
	var clientUDPAddrPtr atomic.Pointer[net.UDPAddr]

	errCh := make(chan error, 3)
	done := make(chan struct{})

	// TCP Connection monitor — if TCP closes, all UDP goroutines must terminate
	go func() {
		var b [1]byte
		_, err := conn.(net.Conn).Read(b[:])
		_ = err
		close(done)
		// Force the blocking UDP read to unblock
		udpConn.Close()
	}()

	// UDP relay goroutine: single goroutine handles reads AND writes
	// to avoid channel overhead and extra goroutines.
	go func() {
		buf := make([]byte, 65535)
		var bytesIn, bytesOut int64
		defer func() {
			if bytesIn > 0 && s.config.BytesAddIn != nil {
				s.config.BytesAddIn(bytesIn)
			}
			if bytesOut > 0 && s.config.BytesAddOut != nil {
				s.config.BytesAddOut(bytesOut)
			}
			if s.config.TrafficCallback != nil && username != "" && (bytesIn+bytesOut) > 0 {
				s.config.TrafficCallback(username, bytesIn+bytesOut)
			}
		}()

		for {
			select {
			case <-done:
				return
			default:
			}

			// Set a short read deadline so we can check `done` periodically
			_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, rAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if isTimeout(err) {
					continue
				}
				select {
				case <-done:
				default:
					errCh <- fmt.Errorf("udp read failed: %w", err)
				}
				return
			}

			// Determine if this packet is from the client or from a target
			curClient := clientUDPAddrPtr.Load()
			isFromClient := false
			if curClient != nil {
				isFromClient = rAddr.String() == curClient.String()
			} else {
				isFromClient = rAddr.IP.String() == clientIP
			}

			if isFromClient {
				// Track inbound bytes
				if s.config.BytesAddIn != nil {
					bytesIn += int64(n)
					if bytesIn >= 1024*1024 {
						s.config.BytesAddIn(bytesIn)
						if s.config.TrafficCallback != nil && username != "" {
							s.config.TrafficCallback(username, bytesIn)
						}
						bytesIn = 0
					}
				}

				// Parse SOCKS5 UDP header
				// IMPORTANT: copy the IP out of buf before reuse
				hdrLen, dstAddr, err := ParseUDPHeader(buf[:n])
				if err != nil {
					s.config.Logger.Warn("socks: invalid UDP header from client", "error", err)
					continue
				}

				var dUDP *net.UDPAddr
				if dstAddr.FQDN != "" {
					_, resolvedIP, err := s.config.Resolver.Resolve(ctx, dstAddr.FQDN)
					if err != nil {
						s.config.Logger.Warn("socks: udp fqdn resolve failed", "error", err)
						continue
					}
					dUDP = &net.UDPAddr{IP: resolvedIP, Port: dstAddr.Port}
				} else {
					// Copy IP to avoid aliasing buf
					ip := make(net.IP, len(dstAddr.IP))
					copy(ip, dstAddr.IP)
					dUDP = &net.UDPAddr{IP: ip, Port: dstAddr.Port}
				}

				// Remember client's actual UDP address (atomic store)
				addrCopy := &net.UDPAddr{
					IP:   make(net.IP, len(rAddr.IP)),
					Port: rAddr.Port,
					Zone: rAddr.Zone,
				}
				copy(addrCopy.IP, rAddr.IP)
				clientUDPAddrPtr.Store(addrCopy)

				// Send raw payload to target
				payload := buf[hdrLen:n]
				nw, werr := udpConn.WriteToUDP(payload, dUDP)
				if werr == nil && nw > 0 && s.config.BytesAddOut != nil {
					bytesOut += int64(nw)
					if bytesOut >= 1024*1024 {
						s.config.BytesAddOut(bytesOut)
						if s.config.TrafficCallback != nil && username != "" {
							s.config.TrafficCallback(username, bytesOut)
						}
						bytesOut = 0
					}
				}
			} else {
				// Packet from Target -> Client
				curClient = clientUDPAddrPtr.Load()
				if curClient == nil {
					continue // Drop if we don't know the client's UDP port yet
				}

				// Build response with SOCKS5 UDP header
				// Copy IP from rAddr to avoid aliasing
				srcIP := make(net.IP, len(rAddr.IP))
				copy(srcIP, rAddr.IP)
				srcSpec := &AddrSpec{IP: srcIP, Port: rAddr.Port}
				packetData := BuildUDPHeader(srcSpec, buf[:n])

				nw, werr := udpConn.WriteToUDP(packetData, curClient)
				if werr == nil && nw > 0 && s.config.BytesAddOut != nil {
					bytesOut += int64(nw)
					if bytesOut >= 1024*1024 {
						s.config.BytesAddOut(bytesOut)
						if s.config.TrafficCallback != nil && username != "" {
							s.config.TrafficCallback(username, bytesOut)
						}
						bytesOut = 0
					}
				}
			}
		}
	}()

	// Wait for done (TCP close) or error
	select {
	case <-done:
		return nil
	case err := <-errCh:
		return err
	}
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

	// Unbound UDP socket to send/receive to the internet targets
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
	_ = tcpConn.SetDeadline(time.Time{}) // Disable timeouts, this is a long-lived tunnel

	// Mutex to serialize TCP writes from the UDP->TCP goroutine
	var tcpWriteMu sync.Mutex

	// Internet -> TCP: read UDP responses and write into TCP stream
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- fmt.Errorf("udp socket read error: %w", err)
				return
			}

			// Copy IP to avoid aliasing buf
			srcIP := make(net.IP, len(rAddr.IP))
			copy(srcIP, rAddr.IP)
			srcSpec := &AddrSpec{IP: srcIP, Port: rAddr.Port}
			socksFrame := BuildUDPHeader(srcSpec, buf[:n])

			// Prepend 16-bit length prefix for TCP framing
			frame := make([]byte, 2+len(socksFrame))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(socksFrame)))
			copy(frame[2:], socksFrame)

			tcpWriteMu.Lock()
			_, err = tcpConn.Write(frame)
			tcpWriteMu.Unlock()
			if err != nil {
				errCh <- fmt.Errorf("tcp write error: %w", err)
				return
			}
		}
	}()

	// TCP -> Internet: read length-prefixed UDP packets and send out
	go func() {
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(tcpConn, lenBuf); err != nil {
				errCh <- fmt.Errorf("tcp read length error: %w", err)
				return
			}

			packetLen := binary.BigEndian.Uint16(lenBuf)
			if packetLen == 0 {
				continue // Keep-alive
			}

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

			var dUDP *net.UDPAddr
			if dstAddr.FQDN != "" {
				_, resolvedIP, err := s.config.Resolver.Resolve(ctx, dstAddr.FQDN)
				if err != nil {
					s.config.Logger.Warn("socks: udp-tcpmux fqdn resolve failed", "error", err)
					continue
				}
				dUDP = &net.UDPAddr{IP: resolvedIP, Port: dstAddr.Port}
			} else {
				// Copy IP to avoid aliasing frameBuf
				ip := make(net.IP, len(dstAddr.IP))
				copy(ip, dstAddr.IP)
				dUDP = &net.UDPAddr{IP: ip, Port: dstAddr.Port}
			}

			payload := frameBuf[hdrLen:]
			if _, err := udpConn.WriteToUDP(payload, dUDP); err != nil {
				s.config.Logger.Warn("socks: udp-tcpmux write to internet failed", "error", err)
			}
		}
	}()

	// Block until either side errors; defer closes udpConn
	err = <-errCh
	return err
}

// isTimeout checks if an error is a network timeout.
func isTimeout(err error) bool {
	type timeout interface {
		Timeout() bool
	}
	if t, ok := err.(timeout); ok {
		return t.Timeout()
	}
	return false
}

// Ensure atomic.Pointer[net.UDPAddr] alignment (for 32-bit platforms).
var _ = unsafe.Sizeof(atomic.Pointer[net.UDPAddr]{})
