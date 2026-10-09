package s5server

import (
	"context"
	"net"

	"github.com/mazixs/S5Core/internal/tcptune"
)

// listenObfs opens the obfs listener, accepting data in a SYN when ObfsTFO
// asks for it. A system without TCP Fast Open is said at debug level and the
// listener works without it.
func (s *Server) listenObfs(addr string) (net.Listener, error) {
	if !s.cfg.ObfsTFO {
		return net.Listen("tcp", addr)
	}
	lc := net.ListenConfig{Control: tcptune.ListenFastOpen(func(err error) {
		s.logger.Debug("obfs: TCP Fast Open is not available, listening without it", "error", err)
	})}
	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	// The option is taken whatever the sysctl says, and then does nothing.
	if mode, ok := tcptune.FastOpenMode(); ok && mode&tcptune.FastOpenServer == 0 {
		s.logger.Warn("OBFS_TFO is on, but net.ipv4.tcp_fastopen does not let the server accept data in a SYN",
			"tcp_fastopen", mode, "want", mode|tcptune.FastOpenClient|tcptune.FastOpenServer)
	}
	return l, nil
}
