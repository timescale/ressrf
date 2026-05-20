package ressrfstatic

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

const defaultDialTimeout = 30 * time.Second

// SafeDialer returns a net.Dialer whose Control hook validates the
// resolved address against the policy before the kernel issues connect().
// This is the canonical defense against DNS rebinding: Go performs the
// DNS lookup, then this hook sees the literal IP and rejects it if denied.
//
// Mirrors go/ressrf/protocol_tcp.go::SafeDialer.
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

// DialContext dials addr after validating against the policy. The primary
// entry point for SSRF-safe TCP connections.
func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if Disabled() {
		return (&net.Dialer{Timeout: defaultDialTimeout}).DialContext(ctx, network, address)
	}
	return p.SafeDialer().DialContext(ctx, network, address)
}

// controlFunc returns a syscall.RawConn Control function that runs after
// Go resolves DNS but before connect() is issued. The address argument
// is always a literal IP at this stage; any non-IP input means something
// upstream skipped DNS and we reject defensively.
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
			err := &BlockedError{Reason: ReasonHostnameInvalid, DetailText: fmt.Sprintf("non-IP address in control hook: %s", host), URL: address}
			p.emitConnectionAttempt("tcp", address, false, string(err.Reason))
			return err
		}

		if err := p.IsNetworkAllowed([]string{ip.String()}); err != nil {
			p.emitConnectionAttempt("tcp", address, false, blockedReason(err))
			return err
		}
		p.emitConnectionAttempt("tcp", address, true, "")
		return nil
	}
}

// emitConnectionAttempt is a no-op when no sink is attached.
func (p *Policy) emitConnectionAttempt(protocol, remoteAddr string, allowed bool, reason string) {
	if p.auditSink == nil {
		return
	}
	p.auditSink.Emit(&ConnectionAttempt{Protocol: protocol, RemoteAddr: remoteAddr, Allowed: allowed, Reason: reason})
}
