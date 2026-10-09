package s5server

import (
	"net"
	"time"
)

// listenerControls is owned by Server.mu, including during startup. Keeping
// this separate from immutable cfg avoids racing unrelated configuration
// readers when a live listener is tuned or replaced.
type listenerControls struct {
	whitelist                                  []net.IP
	read, write, handshake, dial, frame, grace time.Duration
}

func controlsFrom(cfg Config, whitelist []net.IP) listenerControls {
	return listenerControls{whitelist: whitelist, read: cfg.ReadTimeout, write: cfg.WriteTimeout,
		handshake: cfg.HandshakeTimeout, dial: cfg.DialTimeout, frame: cfg.FrameTimeout, grace: cfg.QuotaGrace}
}

func (p *listenerPipeline) applyControls(c listenerControls) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.whitelist = c.whitelist
	p.readTimeout, p.writeTimeout = c.read, c.write
	p.handshakeTimeout = c.handshake
	p.dialTimeout, p.frameTimeout, p.quotaGrace = c.dial, c.frame, c.grace
}
