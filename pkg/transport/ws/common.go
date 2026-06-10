package ws

import "time"

const (
	// wsHandshakeTimeout is the maximum time allowed for the WS handshake.
	wsHandshakeTimeout = 10 * time.Second
	// defaultPingInterval is the base interval for keepalive pings.
	defaultPingInterval = 30 * time.Second
)
