package ressrfstatic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startLoopbackListener returns a TCP listener on 127.0.0.1:0 plus a Cleanup
// hook that closes it. Centralizes the boilerplate every e2e TCP test
// otherwise repeats and avoids leaking listeners on assertion failure.
func startLoopbackListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen on loopback")
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// dialCtx wraps DialContext with a short timeout so test runs that hit a
// blocked address fail fast instead of waiting for the platform default
// (~75s on Linux for a SYN-blackholed dial).
func dialCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 2*time.Second)
}

func TestDialContextBlocksPrivate(t *testing.T) {
	// Real local listener; ExternalOnly should block the dial because
	// 127.0.0.1 is in the IANA loopback deny range.
	ln := startLoopbackListener(t)

	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	require.NoError(t, err)

	ctx, cancel := dialCtx(t)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", ln.Addr().String())
	require.Error(t, err, "dial to loopback should be blocked under ExternalOnly")
	require.ErrorIs(t, err, ErrBlocked)
	require.Nil(t, conn)
}

func TestDialContextAllowsAllowOverride(t *testing.T) {
	ln := startLoopbackListener(t)

	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8").
		Build()
	require.NoError(t, err)

	ctx, cancel := dialCtx(t)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", ln.Addr().String())
	require.NoError(t, err, "allow override should permit loopback")
	require.NotNil(t, conn)
	t.Cleanup(func() { _ = conn.Close() })
}

func TestDialContextDisabledBypass(t *testing.T) {
	ln := startLoopbackListener(t)

	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	require.NoError(t, err)

	DisableForTests(t)

	conn, err := p.DialContext(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err, "DisableForTests should bypass policy checks")
	require.NotNil(t, conn)
	t.Cleanup(func() { _ = conn.Close() })
}

func TestSafeDialerEmitsConnectionAttempt(t *testing.T) {
	ln := startLoopbackListener(t)

	sink := &RecordingSink{}
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8").
		WithAuditSink(sink).
		Build()
	require.NoError(t, err)
	sink.Reset() // drop the PolicyCreated event so the assertion is unambiguous

	ctx, cancel := dialCtx(t)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	var ce *ConnectionAttempt
	for _, e := range sink.Events {
		if got, ok := e.(*ConnectionAttempt); ok && got.Protocol == "tcp" {
			ce = got
			break
		}
	}
	require.NotNil(t, ce, "no ConnectionAttempt(tcp) event among %d events", len(sink.Events))
	require.True(t, ce.Allowed, "expected allowed=true")
	require.Contains(t, ce.RemoteAddr, "127.0.0.1")
}
