// Package httpx provides an SSRF-safe http.RoundTripper and http.Client that
// enforce a ressrf.Policy on every outbound request, every DNS resolution,
// and every redirect hop.
//
// Use Transport to wrap an existing *http.Transport (or http.DefaultTransport)
// while preserving its proxy / TLS / pool settings; use Client for a complete
// *http.Client with the same protections plus per-hop redirect validation.
package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/internal/dialurl"
	"github.com/timescale/ressrf/go-native/ressrf/tcpx"
)

// ErrTooManyRedirects fires when CheckRedirect sees more than MaxRedirectHops
// hops in a single chain.
var ErrTooManyRedirects = errors.New("ressrf: too many redirects")

// MaxRedirectHops is the per-request redirect ceiling enforced by Client.
const MaxRedirectHops = 10

// Option configures Transport / Client at construction time. Composes with
// the same functional-options style as ressrf.NewPolicy.
type Option func(*config)

type config struct {
	base http.RoundTripper
}

// WithBaseTransport wraps an existing RoundTripper. The base is cloned (when
// it is an *http.Transport) so its proxy / TLS / pool settings are preserved
// while DialContext is replaced with the SSRF-checking dialer. Pass this
// when you have a customised *http.Transport you want to layer protection
// on top of.
func WithBaseTransport(rt http.RoundTripper) Option {
	return func(c *config) { c.base = rt }
}

func buildConfig(opts []Option) config {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Transport returns an http.RoundTripper that enforces p on every outgoing
// request. If the base (or http.DefaultTransport when WithBaseTransport is
// not supplied) is an *http.Transport, it is cloned and its DialContext is
// replaced with a Control-hook dialer so DNS-pinned IPs are re-checked at
// socket time. If the base is some other RoundTripper (a mock, a middleware
// chain, etc.), it is wrapped without modification: the URL-time and
// redirect-hop checks still apply, but the dial-time IP recheck is skipped
// because we cannot inject a Control hook into an arbitrary RoundTripper.
func Transport(p *ressrf.Policy, opts ...Option) http.RoundTripper {
	cfg := buildConfig(opts)
	base := cfg.base
	if base == nil {
		base = http.DefaultTransport
	}
	if t, ok := base.(*http.Transport); ok {
		cloned := t.Clone()
		cloned.DialContext = dialContext(p)
		base = cloned
	}
	return &roundTripper{base: base, policy: p}
}

// Client returns a complete *http.Client with SSRF-safe transport plus
// per-hop redirect validation. CheckRedirect blocks plaintext-downgrade and
// caps the chain at MaxRedirectHops.
func Client(p *ressrf.Policy, opts ...Option) *http.Client {
	return &http.Client{
		Transport:     Transport(p, opts...),
		CheckRedirect: checkRedirectFunc(p),
	}
}

// CheckRedirect is exposed standalone for callers wiring their own
// *http.Client around Transport but who still want the per-hop policy check.
func CheckRedirect(p *ressrf.Policy) func(req *http.Request, via []*http.Request) error {
	return checkRedirectFunc(p)
}

type roundTripper struct {
	base   http.RoundTripper
	policy *ressrf.Policy
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if ressrf.Bypassed() {
		return t.base.RoundTrip(req)
	}
	if err := t.policy.IsAllowed(req.Context(), req.URL.String()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func dialContext(p *ressrf.Policy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	safe := tcpx.Dialer(p)
	dialer := &net.Dialer{
		Timeout:   tcpx.DefaultDialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   safe.Control,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !ressrf.Bypassed() {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if err := p.IsAllowed(ctx, dialurl.URLForHost(host)); err != nil {
				return nil, err
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

func checkRedirectFunc(p *ressrf.Policy) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if ressrf.Bypassed() {
			return nil
		}
		if len(via) >= MaxRedirectHops {
			return ErrTooManyRedirects
		}
		url := req.URL.String()
		if err := p.IsAllowed(req.Context(), url); err != nil {
			return err
		}
		if req.URL.Scheme == "http" && len(via) > 0 && via[0].URL.Scheme == "https" {
			return &ressrf.BlockedError{
				Reason: &ressrf.RedirectSchemeDowngrade{From: via[0].URL.Scheme, To: req.URL.Scheme},
				URL:    url,
			}
		}
		return nil
	}
}
