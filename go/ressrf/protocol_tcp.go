package ressrf

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

const defaultDialTimeout = 30 * time.Second

// SafeDialer returns a net.Dialer whose Control hook validates resolved
// addresses against the SSRF policy before allowing the TCP connection.
func (p *Policy) SafeDialer() *net.Dialer {
	return p.SafeDialerWithTimeout(defaultDialTimeout)
}

// SafeDialerWithTimeout returns a SafeDialer with a custom timeout.
func (p *Policy) SafeDialerWithTimeout(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: p.controlFunc(),
	}
}

// DialContext dials the address after validating it against the policy.
// This is the primary entry point for SSRF-safe TCP connections.
func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if Disabled() {
		return (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(ctx, network, address)
	}
	return p.SafeDialer().DialContext(ctx, network, address)
}

// controlFunc returns a syscall.RawConn Control function that checks
// the resolved IP against the policy before allowing connect().
//
// The control hook runs after Go's net.Dialer resolves DNS, so the
// address parameter is always a resolved IP (not a hostname). The
// check uses IsNetworkAllowed (IP-level) rather than IsAllowed
// (URL-level) because the TCP layer has no URL context and the URI
// validator's scheme allowlist would reject synthetic tcp:// URLs.
//
// If the address is unexpectedly a hostname (not a literal IP), the
// connection is rejected as a defensive measure.
func (p *Policy) controlFunc() func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		if Disabled() {
			return nil
		}

		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}

		ip := net.ParseIP(host)
		if ip == nil {
			return &BlockedError{
				Reason: fmt.Sprintf("non-IP address in control hook: %s", host),
				URL:    address,
			}
		}

		if err := p.IsNetworkAllowed(context.Background(), []string{ip.String()}); err != nil {
			return err
		}
		return nil
	}
}
