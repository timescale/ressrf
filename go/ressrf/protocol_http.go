package ressrf

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPTransport returns an http.RoundTripper that enforces the SSRF policy
// on every outgoing HTTP request. It wraps the provided base transport
// (or http.DefaultTransport if nil), preserving proxy settings, TLS config,
// and connection pooling while replacing the dialer with an SSRF-protected
// dialer.
func (p *Policy) HTTPTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}

	var transport *http.Transport
	switch t := base.(type) {
	case *http.Transport:
		transport = t.Clone()
	default:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}

	transport.DialContext = p.httpDialContext(transport.DialContext)

	return &ssrfTransport{
		base:   transport,
		policy: p,
	}
}

// HTTPClient returns a configured *http.Client with SSRF protection on both
// the transport layer (DNS/IP validation) and redirect layer (per-hop check).
func (p *Policy) HTTPClient(base http.RoundTripper) *http.Client {
	return &http.Client{
		Transport:     p.HTTPTransport(base),
		CheckRedirect: p.checkRedirect,
	}
}

type ssrfTransport struct {
	base   http.RoundTripper
	policy *Policy
}

func (t *ssrfTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if Disabled() {
		return t.base.RoundTrip(req)
	}

	url := req.URL.String()
	if err := t.policy.IsAllowed(req.Context(), url); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func (p *Policy) httpDialContext(
	_ func(ctx context.Context, network, addr string) (net.Conn, error),
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   p.controlFunc(),
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !Disabled() {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			url := destinationURLForHost(host)
			if err := p.IsAllowed(ctx, url); err != nil {
				return nil, err
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

func destinationURLForHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("https://[%s]", host)
	}
	return fmt.Sprintf("https://%s", host)
}

func (p *Policy) checkRedirect(req *http.Request, via []*http.Request) error {
	if Disabled() {
		return nil
	}

	if len(via) >= 10 {
		return fmt.Errorf("ressrf: too many redirects (max 10)")
	}

	url := req.URL.String()
	if err := p.IsAllowed(req.Context(), url); err != nil {
		return err
	}

	if req.URL.Scheme == "http" && len(via) > 0 && via[0].URL.Scheme == "https" {
		return &BlockedError{
			Reason: "HTTPS to HTTP downgrade during redirect",
			URL:    url,
		}
	}

	return nil
}
