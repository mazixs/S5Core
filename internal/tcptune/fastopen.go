package tcptune

import (
	"net"
	"syscall"
)

// The bits of net.ipv4.tcp_fastopen: the client may send data in a SYN, the
// server may accept it on a listener that asked for it.
const (
	FastOpenClient = 1
	FastOpenServer = 2
)

// ListenFastOpen is a Control for net.ListenConfig that lets the listening
// socket accept data in a SYN (TCP_FASTOPEN). A refusal goes to refused, not
// to the listen: a server where the kernel has no such option still starts.
func ListenFastOpen(refused func(error)) func(network, address string, c syscall.RawConn) error {
	return fastOpenControl(setListenFastOpen, refused)
}

// DialFastOpen is a Control for net.Dialer that puts the first write of the
// connection into its SYN (TCP_FASTOPEN_CONNECT, Linux 4.11 and later). With
// it connect() sends nothing while the kernel holds a cookie for the server:
// the SYN leaves with the first write. Without a cookie the dial is an
// ordinary one that asks for it. A refusal goes to refused, not to the dial.
func DialFastOpen(refused func(error)) func(network, address string, c syscall.RawConn) error {
	return fastOpenControl(setConnectFastOpen, refused)
}

func fastOpenControl(set func(fd uintptr) error, refused func(error)) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		if cerr := c.Control(func(fd uintptr) { err = set(fd) }); cerr != nil {
			err = cerr
		}
		if err != nil && refused != nil {
			refused(err)
		}
		return nil
	}
}

// SYNData says whether the SYN of the connection under c carried data that
// the peer acknowledged: on the side that dialled, its first write; on the
// side that accepted, what the peer sent with its SYN. ok is false where the
// kernel does not say.
func SYNData(c net.Conn) (carried, ok bool) {
	sc, err := Socket(c)
	if err != nil {
		return false, false
	}
	return synData(sc)
}

// DialsFastOpen says whether the socket under c was dialled with
// TCP_FASTOPEN_CONNECT. ok is false where the kernel does not say.
func DialsFastOpen(c net.Conn) (on, ok bool) {
	sc, err := Socket(c)
	if err != nil {
		return false, false
	}
	return dialsFastOpen(sc)
}

// Why a SYN that the client sent with data did not get the data through,
// tcpi_fastopen_client_fail of Linux 5.5 and later.
const (
	// FastOpenFailUnknown: nothing failed, or a kernel older than 5.5.
	FastOpenFailUnknown = 0
	// FastOpenNoCookie: there was no cookie to send data with.
	FastOpenNoCookie = 1
	// FastOpenDataNotAcked: the server answered the SYN and not its data,
	// with a cookie of its own, as one whose key changed does.
	FastOpenDataNotAcked = 2
	// FastOpenSYNRetransmitted: the SYN with data went unanswered and was
	// sent again without it.
	FastOpenSYNRetransmitted = 3
)

// FastOpenClientFail says why the SYN data of the connection under c, which
// this side dialled, was not acknowledged. ok is false where the kernel does
// not say; a kernel older than 5.5 says FastOpenFailUnknown.
func FastOpenClientFail(c net.Conn) (cause int, ok bool) {
	sc, err := Socket(c)
	if err != nil {
		return FastOpenFailUnknown, false
	}
	return fastOpenClientFail(sc)
}

// SYNSent says whether the connection under c is still waiting for the
// peer's SYN-ACK. Under TCP_FASTOPEN_CONNECT with a cookie, connect() returns
// in that state: the SYN leaves with the first write.
func SYNSent(c net.Conn) (waiting, ok bool) {
	sc, err := Socket(c)
	if err != nil {
		return false, false
	}
	return synSent(sc)
}
