package socks5

import "sync/atomic"

// SessionAccount couples the policy and accounting selected at login.
// Status must revoke a replaced incarnation instead of looking up its name.
type SessionAccount struct {
	Name    string
	Counter *atomic.Int64
	Status  func() SessionStatus
}

// accountFor keeps the legacy callbacks for codec embedders without bound
// authentication. The SDK always supplies AuthContext.Account.
func (s *Server) accountFor(req *Request) (*atomic.Int64, func() SessionStatus) {
	if req.AuthContext != nil && req.AuthContext.Account != nil {
		acct := req.AuthContext.Account
		return acct.Counter, acct.Status
	}
	name := extractUsername(req)
	var counter *atomic.Int64
	var status func() SessionStatus
	if name != "" {
		if s.config.TrafficCounter != nil {
			counter = s.config.TrafficCounter(name)
		}
		if s.config.SessionStatus != nil {
			status = func() SessionStatus { return s.config.SessionStatus(name) }
		}
	}
	return counter, status
}
