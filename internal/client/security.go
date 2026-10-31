package client

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ValidateServerURL permits HTTPS and HTTP on loopback only. Credentials,
// queries and fragments are not valid parts of a server base URL.
func ValidateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("server URL requires a host and must not contain credentials, a query or a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("server URL must use https:// (http:// is permitted only on loopback)")
}

func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// secureTransport checks every request, including refreshes and file transfers.
type secureTransport struct{ base http.RoundTripper }

func (t secureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.RawQuery, u.Fragment = "", "" // signed download/blob URLs may have queries
	if err := ValidateServerURL(u.String()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many redirects")
	}
	if len(via) > 0 && !sameOrigin(req.URL, via[0].URL) {
		return fmt.Errorf("refusing redirect to a different origin")
	}
	return nil
}
