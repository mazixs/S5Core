package socks5

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

type replacingCredentials struct{ after func() }

func (c replacingCredentials) Valid(_, _ string) bool { c.after(); return true }

func TestAccountReplacementDuringPasswordCheckIsRefused(t *testing.T) {
	var replaced atomic.Bool
	account := &SessionAccount{Name: "alice", Counter: new(atomic.Int64), Status: func() SessionStatus {
		if replaced.Load() {
			return SessionExpired
		}
		return SessionAllowed
	}}
	auth := UserPassAuthenticator{Credentials: replacingCredentials{after: func() { replaced.Store(true) }}, BindAccount: func(string) *SessionAccount { return account }}
	request := bytes.NewReader([]byte{1, 5, 'a', 'l', 'i', 'c', 'e', 1, 'p'})
	var response bytes.Buffer
	if _, err := auth.Authenticate(request, &response, "source"); !errors.Is(err, ErrUserAuthFailed) {
		t.Fatalf("replacement authenticated: %v", err)
	}
	if !bytes.Equal(response.Bytes(), []byte{5, 2, 1, 1}) {
		t.Fatalf("replacement got success response: %v", response.Bytes())
	}
}

func TestBoundAccountOverridesReusedNameForTCPAndUDP(t *testing.T) {
	for _, command := range []byte{ConnectCommand, AssociateCommand, UDPTunnelCommand, UDPNativeCommand} {
		t.Run(commandName(command), func(t *testing.T) {
			var oldCounter, newCounter atomic.Int64
			s, err := New(&Config{TrafficCounter: func(string) *atomic.Int64 { return &newCounter }, SessionStatus: func(string) SessionStatus { return SessionAllowed }})
			if err != nil {
				t.Fatal(err)
			}
			account := &SessionAccount{Name: "alice", Counter: &oldCounter, Status: func() SessionStatus { return SessionExpired }}
			req := &Request{Command: command, AuthContext: &AuthContext{Payload: map[string]string{"Username": "alice"}, Account: account}}
			conn := &MockConn{}
			if err := s.handleRequest(context.Background(), req, conn); !errors.Is(err, ErrSessionNotAllowed) {
				t.Fatalf("request authenticated before replacement was accepted: %v", err)
			}
			if command == ConnectCommand {
				toTarget, _ := s.connectHalves(conn, req, nil, nil, func() {})
				if toTarget.Counter != &oldCounter || toTarget.Status() != SessionExpired {
					t.Fatal("TCP adopted replacement account")
				}
			} else {
				acct := s.udpAccountFor(req)
				if acct.counter != &oldCounter || acct.status() != SessionExpired {
					t.Fatal("UDP adopted replacement account")
				}
				meter := newUDPMeter(acct)
				if meter.inbound(udpMeterBatch) != SessionExpired {
					t.Fatal("UDP failed to revoke at billing boundary")
				}
				if oldCounter.Load() != udpMeterBatch || newCounter.Load() != 0 {
					t.Fatal("UDP billed a replacement")
				}
			}
		})
	}
}
