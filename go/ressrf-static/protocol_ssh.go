package ressrfstatic

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHDial opens an SSH connection to addr after validating the target
// against the policy. Mirrors go/ressrf/protocol_ssh.go::SSHDial.
//
// The address goes through two layers of protection:
//  1. A synthetic https:// URL is built from the host and run through
//     IsAllowed — catches scheme-shaped problems (ambiguous IPs, denied
//     suffixes, IP literal in deny range).
//  2. The TCP dial uses SafeDialer, so the Control hook re-checks the
//     resolved IP just before connect(). Defeats DNS rebinding even if
//     the URL-layer check passed.
func (p *Policy) SSHDial(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if Disabled() {
		return ssh.Dial("tcp", addr, config)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = "22"
	}

	synthURL := destinationURLForHost(host)
	if err := p.IsAllowed(ctx, synthURL); err != nil {
		p.emitConnectionAttempt("ssh", addr, false, blockedReason(err))
		return nil, err
	}

	timeout := defaultDialTimeout
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}
	dialer := p.SafeDialerWithTimeout(timeout)
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		// Control-hook denial already emitted ConnectionAttempt(allowed=false)
		// via SafeDialer; we don't double-emit here.
		return nil, fmt.Errorf("ressrfstatic: ssh dial tcp: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ressrfstatic: ssh handshake: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}
	p.emitConnectionAttempt("ssh", addr, true, "")
	return ssh.NewClient(c, chans, reqs), nil
}
