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
			return nil
		}

		cidr := ip.String()
		if ip.To4() != nil {
			cidr += "/32"
		} else {
			cidr += "/128"
		}

		url := fmt.Sprintf("tcp://%s", address)
		if err := p.IsAllowed(context.Background(), url); err != nil {
			return err
		}
		_ = cidr
		return nil
	}
}
