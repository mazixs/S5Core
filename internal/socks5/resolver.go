package socks5

import (
	"fmt"
	"net"

	"context"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}
	if len(ips) == 0 {
		return ctx, nil, fmt.Errorf("no IP addressed found for %s", name)
	}
	return ctx, ips[0], nil
}
