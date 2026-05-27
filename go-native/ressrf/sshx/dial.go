// Package sshx provides an SSRF-safe SSH dialer that validates the target
// against a ressrf.Policy before completing the TCP handshake.
//
// This package is the only one that pulls in golang.org/x/crypto; consumers
// who don't need SSH can import the root ressrf and httpx / tcpx packages
// without paying that dependency cost.
package sshx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/internal/dialurl"
	"github.com/timescale/ressrf/go-native/ressrf/tcpx"
	"golang.org/x/crypto/ssh"
)

// Dial establishes an SSH connection to addr after validating it against p.
// The URL-level check uses an https:// proxy URL (since ssh:// is not in the
// URI validator's default allow-list); the IP-level check is then enforced
// by the underlying SafeDialer's control hook.
func Dial(ctx context.Context, p *ressrf.Policy, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if ressrf.Bypassed() {
		return ssh.Dial("tcp", addr, config)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// SplitHostPort failed; either there is no port or addr is a
		// bracketed IPv6 literal missing a port (e.g. "[::1]"). Strip
		// any enclosing brackets so the JoinHostPort call below does
		// not double-bracket and produce an unparseable address.
		host = strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
		port = "22"
	}

	proxyURL := dialurl.URLForHost(host)
	if err := p.IsAllowed(ctx, proxyURL); err != nil {
		return nil, err
	}

	timeout := tcpx.DefaultDialTimeout
	if config != nil && config.Timeout > 0 {
		timeout = config.Timeout
	}

	dialer := tcpx.Dialer(p, tcpx.WithDialTimeout(timeout))
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("ssh dial tcp: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = c.Close()
		return nil, err
	}

	return ssh.NewClient(c, chans, reqs), nil
}
