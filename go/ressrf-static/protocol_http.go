package ressrfstatic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPTransport returns a RoundTripper that enforces the SSRF policy on
// every outgoing request. Wraps base (or http.DefaultTransport when nil),
// preserving proxy settings, TLS config, and connection pooling while
// replacing the dialer with an SSRF-protected dialer.
//
// Mirrors go/ressrf/protocol_http.go.
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
	return &ssrfTransport{base: transport, policy: p}
}

// HTTPClient returns an *http.Client with SSRF protection at both the
// transport layer (DNS/IP via SafeDialer Control hook) and the redirect
// layer (per-hop policy check + HTTPS→HTTP downgrade block).
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
			synthURL := destinationURLForHost(host)
			if err := p.IsAllowed(ctx, synthURL); err != nil {
				return nil, err
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

// destinationURLForHost builds a synthetic https:// URL for IsAllowed
// when the caller only has a host:port (TCP / DNS-layer code).
func destinationURLForHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return fmt.Sprintf("https://[%s]", host)
	}
	return fmt.Sprintf("https://%s", host)
}

// checkRedirect is plugged in as http.Client.CheckRedirect. Runs on every
// 3xx hop; rejects if the destination fails IsAllowed or if HTTPS is
// downgraded to HTTP mid-chain (CWE-693 / SSL stripping).
func (p *Policy) checkRedirect(req *http.Request, via []*http.Request) error {
	if Disabled() {
		return nil
	}
	if len(via) >= 10 {
		return fmt.Errorf("ressrfstatic: too many redirects (max 10)")
	}
	url := req.URL.String()
	if err := p.IsAllowed(req.Context(), url); err != nil {
		p.emitRedirect(via[len(via)-1].URL.String(), url, false, blockedReason(err))
		return err
	}
	if !p.allowPlaintextHTTP && req.URL.Scheme == "http" && len(via) > 0 && via[0].URL.Scheme == "https" {
		err := &BlockedError{Reason: ReasonURLRuleDenied, URL: url, DetailText: "HTTPS to HTTP downgrade during redirect"}
		p.emitRedirect(via[len(via)-1].URL.String(), url, false, string(err.Reason))
		return err
	}
	p.emitRedirect(via[len(via)-1].URL.String(), url, true, "")
	return nil
}

func (p *Policy) emitRedirect(from, to string, allowed bool, reason string) {
	if p.auditSink == nil {
		return
	}
	p.auditSink.Emit(&RedirectIntercepted{FromURL: from, ToURL: to, Allowed: allowed, Reason: reason})
}
