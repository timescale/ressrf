// Package sshx provides an SSRF-safe SSH dialer that validates the target
// against a ressrf.Policy before completing the TCP handshake.
//
// This package is the only one that pulls in golang.org/x/crypto; consumers
// who don't need SSH can import the root ressrf and httpx / tcpx packages
// without paying that dependency cost.
package sshx

import (
	"context"
	"errors"
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
//
// config must be non-nil. config.Timeout is the total budget for the whole
// operation: the handshake gets what the connect leaves, bounded by one
// absolute deadline. ctx is honored in every phase: ctx expiry or
// cancellation closes the transport socket, which unblocks a stalled
// handshake, and is reported as an error wrapping ctx.Err(). Callers can
// rely on Dial returning within roughly config.Timeout of the call, or at
// ctx expiry when that is sooner.
func Dial(ctx context.Context, p *ressrf.Policy, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	if config == nil {
		return nil, errors.New("sshx: nil ssh.ClientConfig")
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

	// Under ressrftest.DisableForTests both gates return early (IsAllowed and
	// the tcpx control hook check the bypass before touching p), so the
	// bypass path keeps the same ctx and timeout contract as production.
	proxyURL := dialurl.URLForHost(host)
	if err := p.IsAllowed(ctx, proxyURL); err != nil {
		return nil, err
	}

	timeout := tcpx.DefaultDialTimeout
	if config.Timeout > 0 {
		timeout = config.Timeout
	}
	// One absolute deadline for the whole operation, so Timeout is the total
	// budget, not a per-phase one: the handshake gets what the connect
	// leaves. The ctx deadline is deliberately not folded in: the AfterFunc
	// below owns ctx expiry, and two timers firing at the same instant would
	// race on whether the caller sees ctx.Err() or an i/o timeout.
	deadline := time.Now().Add(timeout)

	dialer := tcpx.Dialer(p, tcpx.WithDialTimeout(timeout))
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("ssh dial tcp: %w", err)
	}

	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// ssh.NewClientConn ignores ctx, so ctx expiry closes the socket to
	// unblock the stalled handshake read. Check the cancel before err: the
	// close makes err "use of closed network connection", which would hide
	// the ctx error. Pattern from live-sync #481.
	stopHandshakeCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if !stopHandshakeCancel() {
		// ctx fired, so setup fails whatever the handshake returned. err ==
		// nil means the handshake completed in the gap before the close
		// landed, so discard the connection nobody will use. Not c.Close():
		// NewClient starts the goroutines that drain the mux channels, so
		// loop returns to the read and sees the close.
		if err == nil {
			_ = ssh.NewClient(c, chans, reqs).Close()
		}
		return nil, fmt.Errorf("ssh handshake: %w", ctx.Err())
	}
	if err != nil {
		// NewClientConn already closed conn on handshake failure.
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	// Build the client before clearing the deadline so a failure closes it
	// through the client, for the same mux-drain reason as above.
	client := ssh.NewClient(c, chans, reqs)
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = client.Close()
		return nil, err
	}
	return client, nil
}
