package tlsdecoy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Plan task Ф5-6. A static page is a poor cover story. It has one path, one
// length and one set of headers; a probe that asks for two different URLs and
// gets the same bytes both times has found something that is not a web
// server. The answer is not a better page but a real one: proxy everything
// that is not the tunnel to a site chosen by the operator, and let that site
// answer for itself - including its own 404 for the tunnel's own path.
//
// What this does not do: it does not make the deployment look like the
// upstream site to someone who already knows both. The certificate is still
// ours, the address is still ours, and a probe that compares our answers with
// the upstream's own byte for byte will find the differences listed in
// docs/design/decoy.md. What it does is remove the differences a probe can find
// without knowing what to compare against, which is the position an
// automated scanner is in.

// upstreamTimeouts bound one proxied request. They are deliberately shorter
// than the decoy server's own write timeout, so a slow upstream produces a
// plausible gateway error rather than a connection that hangs until the HTTP
// server gives up - a hang being exactly the sort of thing a well-run site
// does not do.
const (
	upstreamDialTimeout     = 5 * time.Second
	upstreamResponseTimeout = 15 * time.Second
	upstreamIdleTimeout     = 90 * time.Second
	upstreamMaxIdleConns    = 32
)

// ValidateUpstream reports whether a decoy upstream can be used, and returns
// the parsed URL. An empty string is valid and means "serve the built-in
// page".
func ValidateUpstream(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("tlsdecoy: decoy upstream %q is not a URL: %w", raw, err)
	}
	switch {
	case target.Scheme != "http" && target.Scheme != "https":
		return nil, fmt.Errorf("tlsdecoy: decoy upstream %q must be http:// or https://", raw)
	case target.Host == "":
		return nil, fmt.Errorf("tlsdecoy: decoy upstream %q has no host", raw)
	case target.RawQuery != "" || target.Fragment != "":
		return nil, fmt.Errorf("tlsdecoy: decoy upstream %q must not carry a query or a fragment", raw)
	}
	return target, nil
}

// newDecoyProxy builds the reverse proxy for an upstream site.
func newDecoyProxy(target *url.URL, logger *slog.Logger) *httputil.ReverseProxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// Present ourselves as the upstream rather than as whatever
			// name the client used to reach us. A site that answers to a
			// Host it has never heard of is a tell in itself, and this is
			// also what makes virtual hosting work at the far end.
			pr.Out.Host = target.Host

			// SetXForwarded is deliberately not called. Telling the
			// upstream who is browsing would hand a third party the list
			// of addresses that probe this server - including, on a bad
			// day, the addresses of real users - and none of it makes the
			// cover story any better.
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("Forwarded")
		},
		ModifyResponse: func(resp *http.Response) error {
			hideUpstream(resp, target)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// The upstream is not reachable. A real host behind a proxy
			// answers this with a gateway error, so that is what goes out;
			// the operator hears about it in the log, the probe does not.
			logger.Warn("Decoy upstream is unreachable",
				"upstream", target.Host, "path", r.URL.Path, "error", err)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(badGatewayHTML))
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: upstreamDialTimeout}).DialContext,
			ResponseHeaderTimeout: upstreamResponseTimeout,
			IdleConnTimeout:       upstreamIdleTimeout,
			MaxIdleConns:          upstreamMaxIdleConns,
			MaxIdleConnsPerHost:   upstreamMaxIdleConns,
			ForceAttemptHTTP2:     true,
		},
	}
}

// hideUpstream rewrites the places where the upstream names itself in a way
// a browser - or a probe - would act on: a redirect to its own host, and a
// cookie scoped to its own domain. Both would otherwise send the next request
// somewhere other than here, which is both a leak and a broken cover story.
//
// Everything else is passed through untouched, including the body: rewriting
// links inside HTML is a game that cannot be won, and a site mirrored this
// way will always load some of its assets from its own domain. That is the
// documented limit of this decoy, not a bug in it.
func hideUpstream(resp *http.Response, target *url.URL) {
	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && sameHost(u.Host, target.Host) {
			u.Scheme, u.Host = "", ""
			resp.Header.Set("Location", u.String())
		}
	}

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	rewritten := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		rewritten = append(rewritten, dropUpstreamDomain(cookie, target.Host))
	}
	resp.Header.Del("Set-Cookie")
	for _, cookie := range rewritten {
		resp.Header.Add("Set-Cookie", cookie)
	}
}

// dropUpstreamDomain removes a Domain attribute that names the upstream. A
// cookie without one is scoped to the host that sent it, which is this
// server - the behaviour a visitor would expect anyway.
func dropUpstreamDomain(cookie, upstreamHost string) string {
	parts := strings.Split(cookie, ";")
	kept := parts[:0]
	for _, part := range parts {
		attr := strings.TrimSpace(part)
		if name, value, found := strings.Cut(attr, "="); found &&
			strings.EqualFold(strings.TrimSpace(name), "domain") &&
			sameHost(strings.TrimPrefix(strings.TrimSpace(value), "."), upstreamHost) {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, ";")
}

// sameHost compares two host values, ignoring the port and letter case.
func sameHost(a, b string) bool {
	if host, _, err := net.SplitHostPort(a); err == nil {
		a = host
	}
	if host, _, err := net.SplitHostPort(b); err == nil {
		b = host
	}
	return a != "" && strings.EqualFold(a, b)
}

// badGatewayHTML is what a visitor sees when the upstream is down. It names
// no server software: a page claiming to be produced by one proxy while the
// headers say another is a difference a probe can see.
const badGatewayHTML = `<!DOCTYPE html>
<html>
<head><title>502 Bad Gateway</title></head>
<body>
<h1>502 Bad Gateway</h1>
<p>The server encountered a temporary error and could not complete your request.</p>
</body>
</html>
`
