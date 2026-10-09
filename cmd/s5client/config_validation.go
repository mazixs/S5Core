package main

import (
	"encoding/hex"
	"errors"
	"net/url"
	"strings"

	"github.com/mazixs/S5Core/pkg/obfs"
)

// Validation errors name settings, never an untrusted URL or credential.
func validateClientWireConfig(cfg clientParams) error {
	if err := obfs.ValidateMTU(cfg.MTU); err != nil {
		return err
	}
	if cfg.MaxPadding < 0 || cfg.MaxPadding > 4096 {
		return errors.New("OBFS_MAX_PADDING must be between 0 and 4096")
	}
	if len(cfg.ProxyUser) > 255 || len(cfg.ProxyPass) > 255 {
		return errors.New("PROXY_USER and PROXY_PASS must not exceed 255 bytes")
	}
	if cfg.WSUrl != "" {
		u, err := url.Parse(cfg.WSUrl)
		if err != nil || u == nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "ws" && u.Scheme != "wss") {
			return errors.New("WS_URL requires a ws/wss URL without credentials or fragment")
		}
		if u.Scheme == "ws" && len(cfg.WSPins) > 0 {
			return errors.New("WS_PIN_SHA256 requires wss TLS")
		}
	}
	for _, pin := range cfg.WSPins {
		b, err := hex.DecodeString(strings.TrimSpace(pin))
		if err != nil || len(b) != 32 {
			return errors.New("WS_PIN_SHA256 requires 64 hexadecimal characters per pin")
		}
	}
	return nil
}
