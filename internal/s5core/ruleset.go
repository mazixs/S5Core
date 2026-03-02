package s5core

import (
	"context"
	"regexp"

	"github.com/mazixs/S5Core/internal/socks5"
)

// PermitDestAddrPattern returns a RuleSet which selectively allows addresses
func PermitDestAddrPattern(pattern string) (socks5.RuleSet, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &PermitDestAddrPatternRuleSet{re}, nil
}

// PermitDestAddrPatternRuleSet is an implementation of the RuleSet which
// enables filtering supported destination address
type PermitDestAddrPatternRuleSet struct {
	AllowedFqdnPattern *regexp.Regexp
}

func (p *PermitDestAddrPatternRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	match := p.AllowedFqdnPattern.MatchString(req.DestAddr.FQDN)
	return ctx, match
}
