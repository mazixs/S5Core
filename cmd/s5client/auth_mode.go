package main

import "fmt"

// auto preserves existing configurations. member-only explicitly pipelines
// CONNECT without password negotiation or fallback to the legacy format.
func validateAuthMode(cfg clientParams) error {
	switch cfg.AuthMode {
	case "", "auto":
		return nil
	case "member-only":
		if cfg.MemberID == "" || cfg.MemberKey == "" {
			return fmt.Errorf("PROXY_AUTH_MODE=member-only requires OBFS_MEMBER_ID and OBFS_MEMBER_KEY")
		}
		if _, err := memberKey(cfg); err != nil {
			return err
		}
		if cfg.ProxyUser != "" || cfg.ProxyPass != "" {
			return fmt.Errorf("PROXY_AUTH_MODE=member-only forbids PROXY_USER/PROXY_PASS; use password-fallback for method negotiation")
		}
		if cfg.Format != string(formatV1) {
			return fmt.Errorf("PROXY_AUTH_MODE=member-only requires OBFS_FORMAT=v1 (no legacy fallback)")
		}
	case "password-fallback":
		if cfg.ProxyUser == "" || cfg.ProxyPass == "" {
			return fmt.Errorf("PROXY_AUTH_MODE=password-fallback requires PROXY_USER and PROXY_PASS")
		}
	default:
		return fmt.Errorf("PROXY_AUTH_MODE must be auto, member-only or password-fallback")
	}
	return nil
}
