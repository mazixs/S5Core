package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mazixs/S5Core/pkg/obfs"
)

func TestWireConfigRefusesMalformedAndUnsafeSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  clientParams
	}{
		{"MTU overflow", clientParams{MTU: obfs.MaxMTU + 1}},
		{"negative MTU", clientParams{MTU: -1}},
		{"pin", clientParams{WSPins: []string{"not-hex"}}},
		{"cleartext pin", clientParams{WSUrl: "ws://example.invalid/ws", WSPins: []string{strings.Repeat("01", 32)}}},
		{"broken URL", clientParams{WSUrl: "wss://secret:private@["}},
		{"URL credentials", clientParams{WSUrl: "wss://secret:private@example.invalid/ws"}},
		{"long username", clientParams{ProxyUser: strings.Repeat("x", 256)}},
		{"long password", clientParams{ProxyPass: strings.Repeat("x", 256)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClientWireConfig(tc.cfg)
			if err == nil {
				t.Fatal("invalid setting accepted")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
				t.Fatal("validation leaked credentials")
			}
		})
	}
	if err := validateClientWireConfig(clientParams{MTU: obfs.MaxMTU, WSUrl: "wss://example.invalid/ws", WSPins: []string{strings.Repeat("01", 32)}, ProxyUser: strings.Repeat("u", 255), ProxyPass: strings.Repeat("p", 255)}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthResponseRequiresItsVersion(t *testing.T) {
	if err := readUserPassAuthResponse(bytes.NewReader([]byte{2, 0})); err == nil {
		t.Fatal("wrong auth version accepted")
	}
	if err := readUserPassAuthResponse(bytes.NewReader([]byte{1, 0})); err != nil {
		t.Fatal(err)
	}
}
