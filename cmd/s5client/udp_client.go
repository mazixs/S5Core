package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
)

// handleUDPAssociate handles the client side of UDP Associate.
// It opens a local UDP socket, tells the application its address,
// and then multiplexes UDP packets over the obfuscated TCP tunnel.
func handleUDPAssociate(clientConn net.Conn, obfsConn net.Conn, connectReq []byte) {
	// 1. Read CONNECT response from server (for the 0x83 UDPTcpMux command)
	slog.Info("UDP Associate: waiting for server reply on 0x83...")
	connectResp := make([]byte, 256)
	rn, err := obfsConn.Read(connectResp)
	if err != nil {
		slog.Error("Failed to read UDP Associate response from server", "error", err)
		return
	}
	if rn >= 2 && connectResp[1] != 0x00 {
		slog.Error("Server rejected UDP-over-TCP tunnel", "status", connectResp[1])
		clientConn.Write(connectResp[:rn]) //nolint:errcheck
		return
	}

	// 2. Open a local UDP socket for the application to send packets to
	// We bind to the same IP the client connected to (usually 127.0.0.1)
	localIP, _, _ := net.SplitHostPort(clientConn.LocalAddr().String())
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(localIP, "0"))
	if err != nil {
		slog.Error("Failed to resolve bind address", "ip", localIP, "error", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		slog.Error("Failed to bind local UDP socket", "error", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}
	defer udpConn.Close()

	// 3. Send success response to application with our local UDP port
	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	// BuildUDPHeader adds RSV+FRAG which we don't want for the TCP reply,
	// we just want standard SOCKS5 reply format: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	// Actually, socks5.BuildUDPHeader produces exactly RSV(0,0) FRAG(0) ATYP ... which happens to match VER(5) REP(0) RSV(0) ATYP ... if we tweak it.
	// But it's safer to build by hand:
	var atyp byte
	var addrLen int
	var ipBytes []byte

	if ip := boundAddr.IP.To4(); ip != nil {
		atyp = 0x01
		addrLen = 4
		ipBytes = ip
	} else {
		atyp = 0x04
		addrLen = 16
		ipBytes = boundAddr.IP.To16()
	}

	tcpReply := make([]byte, 4+addrLen+2)
	tcpReply[0] = 0x05 // VER
	tcpReply[1] = 0x00 // REP Success
	tcpReply[2] = 0x00 // RSV
	tcpReply[3] = atyp // ATYP
	copy(tcpReply[4:], ipBytes)
	binary.BigEndian.PutUint16(tcpReply[4+addrLen:], uint16(boundAddr.Port))

	if _, err := clientConn.Write(tcpReply); err != nil {
		slog.Error("Failed to send UDP Associate reply", "error", err)
		return
	}

	slog.Info("UDP Tunnel established", "local_udp", boundAddr.String())

	// 4. Multiplexing Loop
	errCh := make(chan error, 2)
	clientUDPAddr := &net.UDPAddr{} // We learn this from the first incoming packet

	// Go routine A: Read from application (UDP) -> write to obfsConn (TCP)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, rAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- fmt.Errorf("local udp read failed: %w", err)
				return
			}

			// Validate it's from the same IP as the TCP connection
			appIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
			if rAddr.IP.String() != appIP {
				continue // Drop packets from strangers
			}
			clientUDPAddr = rAddr

			// The packet from the application MUST start with a SOCKS5 UDP header
			// We just tunnel this entire frame verbatim inside length-prefixed TCP
			frame := make([]byte, 2+n)
			binary.BigEndian.PutUint16(frame[0:2], uint16(n))
			copy(frame[2:], buf[:n])

			if _, err := obfsConn.Write(frame); err != nil {
				errCh <- fmt.Errorf("tunnel write failed: %w", err)
				return
			}
		}
	}()

	// Go routine B: Read from obfsConn (TCP) -> write to application (UDP)
	go func() {
		lenBuf := make([]byte, 2)
		for {
			// Read 16-bit length prefix
			if _, err := io.ReadFull(obfsConn, lenBuf); err != nil {
				errCh <- fmt.Errorf("tunnel read length failed: %w", err)
				return
			}

			packetLen := binary.BigEndian.Uint16(lenBuf)
			if packetLen == 0 {
				continue // keep-alive
			}

			// Read inner SOCKS5 UDP frame
			frameBuf := make([]byte, packetLen)
			if _, err := io.ReadFull(obfsConn, frameBuf); err != nil {
				errCh <- fmt.Errorf("tunnel read frame failed: %w", err)
				return
			}

			// Must know where the client is to send UDP back
			if clientUDPAddr.IP == nil {
				slog.Warn("Dropping returning UDP packet because client address unknown")
				continue
			}

			if _, err := udpConn.WriteToUDP(frameBuf, clientUDPAddr); err != nil {
				slog.Warn("Failed to send UDP packet to application", "error", err)
			}
		}
	}()

	// Go routine C: Monitor TCP connection from application
	go func() {
		var b [1]byte
		_, err := clientConn.Read(b[:])
		errCh <- fmt.Errorf("app tcp connection closed: %v", err)
	}()

	// Wait for any critical failure
	err = <-errCh
	slog.Info("UDP Tunnel closed", "reason", err)
}
