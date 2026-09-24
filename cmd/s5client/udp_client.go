package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/mazixs/S5Core/internal/socks5"
	"github.com/mazixs/S5Core/internal/tcptune"
)

var (
	udpReadBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535)
			return &b
		},
	}
	udpFramePool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535+2)
			return &b
		},
	}
)

// SOCKS5 address types, as a reply spells them (RFC 1928, section 6).
const (
	addrIPv4 = 0x01
	addrFQDN = 0x03
	addrIPv6 = 0x04
)

// readSOCKSReply reads exactly one SOCKS5 reply from the tunnel and stops
// there, leaving whatever follows for the caller.
//
// A reply is not a packet. This used to be one Read into a 256-byte buffer,
// judged by what happened to arrive: a lone VER byte failed the "rn >= 2"
// test, so the status byte that had not arrived yet was taken for success,
// the application was told its UDP tunnel was up, and the rest of the reply
// was then read by the frame loop as 16-bit frame lengths - the first two
// bytes of it are REP and RSV, which spell a length of zero, and the next two
// are ATYP and the first octet of the bound address, which spell several
// hundred (audit finding F14).
//
// Taking the fixed part first and the address second consumes the bytes of the
// reply and nothing else, so a server that sends its reply and the first frame
// in one write is read correctly, and a server that sends half a reply and
// stops is an error rather than a success.
func readSOCKSReply(r io.Reader) ([]byte, error) {
	head := make([]byte, 4, 5)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("reading the reply header: %w", err)
	}
	if head[0] != socks5Ver {
		return nil, fmt.Errorf("reply version %#x, want %#x", head[0], socks5Ver)
	}
	if head[2] != 0x00 {
		return nil, fmt.Errorf("reply reserved byte %#x, want 0x00", head[2])
	}

	var addrLen int
	switch head[3] {
	case addrIPv4:
		addrLen = net.IPv4len
	case addrIPv6:
		addrLen = net.IPv6len
	case addrFQDN:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, fmt.Errorf("reading the length of the bound name: %w", err)
		}
		if n[0] == 0 {
			return nil, fmt.Errorf("reply names a bound address of zero length")
		}
		head = append(head, n[0])
		addrLen = int(n[0])
	default:
		return nil, fmt.Errorf("reply address type %#x, want one of %#x, %#x, %#x", head[3], addrIPv4, addrFQDN, addrIPv6)
	}

	reply := make([]byte, len(head)+addrLen+2)
	copy(reply, head)
	if _, err := io.ReadFull(r, reply[len(head):]); err != nil {
		return nil, fmt.Errorf("reading the bound address: %w", err)
	}
	return reply, nil
}

// addrOf is the IP an address names, unmapped so that an IPv4 peer compares
// equal however the socket it arrived on spells it, or the zero Addr if the
// address names no IP at all - a connection over a pipe or a Unix socket,
// which has no datagram source that could match it.
func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// socksUDPHeader reports whether d starts with a header the server's
// socks5.ParseUDPHeader accepts. It checks the same things without building
// the address, because it runs on every datagram.
func socksUDPHeader(d []byte) bool {
	if len(d) < 4 || d[0] != 0 || d[1] != 0 || d[2] != 0 {
		return false
	}
	switch d[3] {
	case addrIPv4:
		return len(d) >= 4+net.IPv4len+2
	case addrIPv6:
		return len(d) >= 4+net.IPv6len+2
	case addrFQDN:
		return len(d) >= 5 && len(d) >= 5+int(d[4])+2
	}
	return false
}

// tuneUDPTunnel is shared by all associations, so that an option the kernel
// refuses is logged once rather than per association.
var tuneUDPTunnel = tcptune.Tuner(nil)

// handleUDPAssociate handles the client side of UDP Associate.
// It opens a local UDP socket, tells the application its address,
// and then multiplexes UDP packets over the obfuscated TCP tunnel.
func handleUDPAssociate(clientConn net.Conn, obfsConn net.Conn, destFQDN string, cfg clientParams) {
	// 1. Read CONNECT response from server (for the 0x83 UDPTcpMux command).
	// This read is still covered by the handshake deadline set in
	// dialObfsTunnel: the custom 0x83 command is the one place where a server
	// that does not understand it would simply never answer.
	slog.Info("UDP Associate: waiting for server reply on 0x83...")
	serverReply, err := readSOCKSReply(obfsConn)
	if err != nil {
		wrapped := &tunnelError{phase: phaseConnectReply, err: err}
		logTunnelFailure(wrapped, destFQDN, cfg)
		_, _ = clientConn.Write([]byte{socks5Ver, replyForTunnelError(wrapped), 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// The tunnel is up; the relay below must not inherit the setup deadline.
	clearDeadline(obfsConn)
	if serverReply[1] != 0x00 {
		slog.Error("Server rejected UDP-over-TCP tunnel", "status", serverReply[1])
		_, _ = clientConn.Write(serverReply)
		return
	}
	if cfg.UDPTunnelTCPTuning {
		tuneUDPTunnel(obfsConn)
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
		_, _ = clientConn.Write([]byte{socks5Ver, socks5GenFailure, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General failure
		return
	}
	defer func() { _ = udpConn.Close() }()

	// 3. Send success response to application with our local UDP port
	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	// VER, REP=success, RSV, then BND.ADDR and BND.PORT.
	tcpReply := socks5.AppendAddr([]byte{socks5Ver, 0x00, 0x00}, &socks5.AddrSpec{IP: boundAddr.IP, Port: boundAddr.Port})

	if _, err := clientConn.Write(tcpReply); err != nil {
		slog.Error("Failed to send UDP Associate reply", "error", err)
		return
	}

	slog.Info("UDP Tunnel established", "local_udp", boundAddr.String())

	// 4. Multiplexing Loop
	errCh := make(chan error, 3)
	var clientUDPAddr atomic.Pointer[netip.AddrPort]

	// The application may send datagrams from the address it opened the SOCKS5
	// connection from, and from nothing else: the port this client announced
	// is reachable by anything on the machine. That address is fixed for the
	// life of the association, so it is taken once here rather than rendered
	// to a string and parsed again on every datagram (review finding R11).
	// This loop is the whole UDP path of a client that runs on an ARM router
	// under GOMEMLIMIT=32MiB (docs/benchmarks/arm-router.md). A datagram used
	// to cost seven allocations: four of them were this check, and the other
	// three were the address itself - one for the *net.UDPAddr the kernel
	// path builds per read, two for the copy of it stored below. Reading and
	// writing through the netip API removes those as well, so the steady
	// state of the loop allocates nothing at all
	// (docs/benchmarks/udp-over-tcp.md).
	appIP := addrOf(clientConn.RemoteAddr())
	if !appIP.IsValid() {
		slog.Warn("UDP Associate: the application's address is not an IP, so no datagram can match it",
			"addr", clientConn.RemoteAddr())
	}

	// Go routine A: Read from application (UDP) -> write to obfsConn (TCP)
	go func() {
		bufPtr := udpReadBufPool.Get().(*[]byte)
		buf := *bufPtr
		defer udpReadBufPool.Put(bufPtr)
		for {
			n, src, err := udpConn.ReadFromUDPAddrPort(buf)
			if err != nil {
				errCh <- fmt.Errorf("local udp read failed: %w", err)
				return
			}

			// Validate it's from the same IP as the TCP connection
			if src.Addr().Unmap() != appIP {
				continue // Drop packets from strangers
			}
			// A datagram without a SOCKS5 UDP header is not the application
			// speaking: the server would refuse it, and taking its port below
			// would send every answer of the association there. A reflector
			// answering a stale port did exactly that, and the answers it got
			// back carried a valid header, so the two ends looped
			// (docs/benchmarks/matrix-2026-09-22/README.md).
			if !socksUDPHeader(buf[:n]) {
				continue
			}

			// Where the answers go. Stored only when it changes, which is
			// once per association unless the application opens another
			// socket: the address is a value, and storing a value needs a
			// pointer to put it behind.
			if cur := clientUDPAddr.Load(); cur == nil || *cur != src {
				stored := src
				clientUDPAddr.Store(&stored)
			}

			// The packet from the application MUST start with a SOCKS5 UDP header
			// We just tunnel this entire frame verbatim inside length-prefixed TCP
			framePtr := udpFramePool.Get().(*[]byte)
			frame := (*framePtr)[:2+n]
			binary.BigEndian.PutUint16(frame[0:2], uint16(n))
			copy(frame[2:], buf[:n])

			if _, err := obfsConn.Write(frame); err != nil {
				udpFramePool.Put(framePtr)
				errCh <- fmt.Errorf("tunnel write failed: %w", err)
				return
			}
			udpFramePool.Put(framePtr)
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
			framePtr := udpFramePool.Get().(*[]byte)
			frameBuf := (*framePtr)[:packetLen]
			if _, err := io.ReadFull(obfsConn, frameBuf); err != nil {
				udpFramePool.Put(framePtr)
				errCh <- fmt.Errorf("tunnel read frame failed: %w", err)
				return
			}

			// Must know where the client is to send UDP back
			addr := clientUDPAddr.Load()
			if addr == nil {
				slog.Warn("Dropping returning UDP packet because client address unknown")
				udpFramePool.Put(framePtr)
				continue
			}

			_, err := udpConn.WriteToUDPAddrPort(frameBuf, *addr)
			udpFramePool.Put(framePtr)
			if errors.Is(err, net.ErrClosed) {
				// The association is being torn down; answers still in the
				// tunnel have nowhere to go.
				errCh <- err
				return
			}
			if err != nil {
				slog.Warn("Failed to send UDP packet to application", "error", err)
			}
		}
	}()

	// Go routine C: Monitor TCP connection from application
	go func() {
		var b [1]byte
		_, err := clientConn.Read(b[:])
		errCh <- fmt.Errorf("app tcp connection closed: %w", err)
	}()

	// Wait for any critical failure
	err = <-errCh
	slog.Info("UDP Tunnel closed", "reason", err)
}
