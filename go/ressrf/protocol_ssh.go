package ressrf

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHDial establishes an SSH connection to the given address after
// validating it against the SSRF policy. It uses SafeDialer to ensure
// DNS-resolved IPs are checked before the TCP handshake.
func (p *Policy) SSHDial(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if Disabled() {
		return ssh.Dial("tcp", addr, config)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "22"
	}

	// Validate the host as an HTTPS URL for URL-level checks (scheme
	// allowlist, domain suffix, ambiguous IP detection). The ssh:// scheme
	// is not in the URI validator's default allowlist, so we use https://
	// as a proxy for "is this destination safe to connect to?". The IP-level
	// check is then enforced by the SafeDialer's control hook.
	proxyURL := destinationURLForHost(host)
	if err := p.IsAllowed(ctx, proxyURL); err != nil {
		return nil, err
	}

	timeout := defaultDialTimeout
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	dialer := p.SafeDialerWithTimeout(timeout)
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("ressrf: ssh dial tcp: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ressrf: ssh handshake: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}
