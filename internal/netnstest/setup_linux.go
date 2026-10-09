package netnstest

import (
	"os"

	"golang.org/x/sys/unix"
)

// setUp brings loopback up and lets both ends of a connection use TCP Fast
// Open. A new namespace starts with loopback down and tcp_fastopen at 1.
func setUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return err
	}
	return os.WriteFile("/proc/sys/net/ipv4/tcp_fastopen", []byte("3\n"), 0)
}
