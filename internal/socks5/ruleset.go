package socks5

import (
	"context"
)

// RuleSet is used to provide custom rules to allow or prohibit actions.
//
// It is asked twice on a UDP association: once for the ASSOCIATE request
// itself, and once for every datagram that association carries, with
// Request.Datagram set and DestAddr naming that datagram's destination. The
// second question is the one about destinations - see Request.Datagram - and
// it is asked before the name is resolved and before anything is sent, so a
// refusal leaves no trace outside this process.
type RuleSet interface {
	Allow(ctx context.Context, req *Request) (context.Context, bool)
}

// PermitAll returns a RuleSet which allows all types of connections
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitCommand is an implementation of the RuleSet which
// enables filtering supported commands
type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

func (p *PermitCommand) Allow(ctx context.Context, req *Request) (context.Context, bool) {
	switch req.Command {
	case ConnectCommand:
		return ctx, p.EnableConnect
	case BindCommand:
		return ctx, p.EnableBind
	case AssociateCommand, UDPTunnelCommand:
		return ctx, p.EnableAssociate
	}

	return ctx, false
}
