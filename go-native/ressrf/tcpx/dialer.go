// Package tcpx provides an SSRF-safe net.Dialer that validates resolved IPs
// against a ressrf.Policy in the Control hook. Use Dial / DialContext as
// drop-in replacements, or grab the dialer via Dialer for composition with
// other net.Dialer-aware APIs.
package tcpx

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/timescale/ressrf/go-native/ressrf"
)

// DefaultDialTimeout is the timeout applied by Dialer and DialContext when
// WithDialTimeout is not supplied.
const DefaultDialTimeout = 30 * time.Second

// Option configures a Dialer at construction time. Options compose with
// ressrf.NewPolicy's functional-options style.
type Option func(*config)

type config struct {
	timeout time.Duration
}

// WithDialTimeout overrides the default 30s dial timeout.
func WithDialTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

func buildConfig(opts []Option) config {
	cfg := config{timeout: DefaultDialTimeout}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Dialer returns a net.Dialer whose Control hook validates resolved addresses
// against p before allowing the TCP connection.
func Dialer(p *ressrf.Policy, opts ...Option) *net.Dialer {
	cfg := buildConfig(opts)
	return &net.Dialer{
		Timeout: cfg.timeout,
		Control: controlFunc(p),
	}
}

// DialContext dials address after validating it against p. Primary entry
// point for SSRF-safe TCP connections.
func DialContext(ctx context.Context, p *ressrf.Policy, network, address string, opts ...Option) (net.Conn, error) {
	if ressrf.Bypassed() {
		return (&net.Dialer{Timeout: buildConfig(opts).timeout}).DialContext(ctx, network, address)
	}
	return Dialer(p, opts...).DialContext(ctx, network, address)
}

// controlFunc is the syscall.RawConn Control function that checks the
// resolved IP against p before allowing connect().
//
// The control hook runs after Go's net.Dialer resolves DNS, so the address
// parameter is always a resolved IP. The check uses IsNetworkAllowed
// (IP-level) rather than IsAllowed (URL-level) because the TCP layer has no
// URL context and the URI validator's scheme allowlist would reject a
// synthetic tcp:// URL.
//
// A non-IP address arriving here would indicate Go's resolver behaving
// unexpectedly; reject defensively.
func controlFunc(p *ressrf.Policy) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		if ressrf.Bypassed() {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return &ressrf.BlockedError{
				Detail: "non-IP address in control hook",
				Host:   host,
				URL:    address,
			}
		}
		return p.IsNetworkAllowedAddrs(context.Background(), []netip.Addr{addr})
	}
}
