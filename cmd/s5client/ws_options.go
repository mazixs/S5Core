package main

import "github.com/mazixs/S5Core/pkg/transport/ws"

func (cfg clientParams) wsOptions() ws.DialOpts {
	return ws.DialOpts{URL: cfg.WSUrl, Host: cfg.WSHost, ServerName: cfg.ServerName, Origin: cfg.WSOrigin, UserAgent: cfg.WSUserAgent, TLSFingerprint: cfg.TLSFingerprint, RootCAs: cfg.rootCAs, PinSHA256: cfg.WSPins}
}
