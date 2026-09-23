package socks5

import (
	"fmt"
	"net"
	"time"

	"context"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// MultiNameResolver optionally supplies all addresses for CONNECT. Legacy
// NameResolver implementations retain their single-address contract.
type MultiNameResolver interface {
	NameResolver
	ResolveAll(context.Context, string) (context.Context, []net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ctx, ips, err := d.ResolveAll(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, ips[0], nil
}

func (d DNSResolver) ResolveAll(ctx context.Context, name string) (context.Context, []net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, fmt.Errorf("no IP addresses found for %s", name)
	}
	return ctx, ips, nil
}

// resolveWithin looks a name up under a budget of its own, and is how the UDP
// paths resolve: there, one lookup per datagram happens on the goroutine that
// reads the client's socket, so a resolver that never answers stops the whole
// association and not just the datagram that asked (audit finding F12). A
// budget of zero means the caller has none to give.
func (s *Server) resolveWithin(ctx context.Context, budget time.Duration, name string) (net.IP, error) {
	if budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}
	_, ip, err := s.config.Resolver.Resolve(ctx, name)
	return ip, err
}

// keepValues carries a resolver's values forward without its deadline.
//
// NameResolver.Resolve returns a context so that a custom resolver can attach
// what it learned to the rest of the request. Handing that context straight
// back used to mean handing back whatever deadline the lookup ran under as
// well, and everything after the lookup - the dial, the reply, the relay that
// lasts as long as the connection - would have inherited it.
func keepValues(lifetime, values context.Context) context.Context {
	if values == nil || values == lifetime {
		return lifetime
	}
	return valueContext{Context: lifetime, values: values}
}

// valueContext answers about time and cancellation from the connection, and
// about values from the resolver.
type valueContext struct {
	context.Context
	values context.Context
}

func (c valueContext) Value(key any) any { return c.values.Value(key) }

// AfterFunc lets a context derived from this one attach to the lifetime
// directly. Without it context.WithTimeout cannot find the lifetime's
// cancelCtx - Value answers from the resolver - and parks a goroutine per
// derived context to watch Done, one per dial attempt.
func (c valueContext) AfterFunc(f func()) func() bool { return context.AfterFunc(c.Context, f) }
