package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ipapiTimezoneURL returns the URL for fetching the timezone of a given IP.
func ipapiTimezoneURL(ip string) string {
	return fmt.Sprintf("https://ipapi.co/%s/timezone/", ip)
}

// detectServerTimezone performs a best-effort GeoIP lookup for the server's
// timezone using ipapi.co. This leaks the client's IP to the API during bootstrap.
// Returns empty string on failure (private IPs, timeouts, etc.).
func detectServerTimezone(serverAddr string) string {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(ipapiTimezoneURL(ip.String()))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var tz string
	if _, err := fmt.Fscan(resp.Body, &tz); err != nil {
		return ""
	}
	return strings.TrimSpace(tz)
}

// systemTimezone returns the current system timezone name, or "" if unknown.
func systemTimezone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		return tz
	}
	// Try to resolve /etc/localtime symlink
	if path, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		// path looks like /usr/share/zoneinfo/Europe/Moscow
		if idx := strings.Index(path, "zoneinfo/"); idx != -1 {
			return path[idx+len("zoneinfo/"):]
		}
	}
	return ""
}

// checkTimezone prints a warning if the system timezone does not match the
// server's geo-timezone. It also prints a ready-to-use wrapper script.
func checkTimezone(serverAddr string) {
	serverTZ := detectServerTimezone(serverAddr)
	if serverTZ == "" {
		return
	}

	sysTZ := systemTimezone()
	if sysTZ == "" {
		sysTZ = "(unknown)"
	}

	if sysTZ == serverTZ {
		return
	}

	fmt.Fprintf(os.Stderr, `
⚠️  TIMEZONE MISMATCH DETECTED
   Server IP timezone:  %s
   Your system timezone: %s

   Websites may detect this discrepancy and flag your account.
   To fix it, launch your browser with the correct timezone:

      TZ=%s firefox &

   Or save this wrapper script:

%s
`, serverTZ, sysTZ, serverTZ, generateWrapperScript(serverTZ))
}

// generateWrapperScript returns a shell script that exports TZ and LC_*
// variables before launching a command.
func generateWrapperScript(tz string) string {
	return fmt.Sprintf(`   #!/bin/sh
   export TZ=%q
   export LC_TIME=%q
   export LC_ALL=%q
   exec "$@"
`, tz, tz, tz)
}
