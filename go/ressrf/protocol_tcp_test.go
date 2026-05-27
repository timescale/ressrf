package ressrf

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/timescale/ressrf/go/ressrf/ressrftest"
)

func buildExternalPolicy(t *testing.T) *Policy {
	t.Helper()
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16").
		Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSafeDialerBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	dialer := p.SafeDialerWithTimeout(1 * time.Second)

	_, err := dialer.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	if err == nil {
		t.Fatal("expected error dialing private IP, got nil")
	}
}

func TestSafeDialerBlocksLoopback(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	dialer := p.SafeDialerWithTimeout(1 * time.Second)

	_, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:8080")
	if err == nil {
		t.Fatal("expected error dialing loopback, got nil")
	}
}

func TestSafeDialerBlocksLinkLocal(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	dialer := p.SafeDialerWithTimeout(1 * time.Second)

	_, err := dialer.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("expected error dialing link-local IMDS, got nil")
	}
}

func TestDialContextRespectsDisableForTests(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	ressrftest.DisableForTests(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind localhost listener")
	}
	defer func() { _ = ln.Close() }()

	conn, err := p.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected success with disabled policy, got: %v", err)
	}
	_ = conn.Close()
}

func TestIsNetworkAllowedPublicIP(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	err := p.IsNetworkAllowed(context.Background(), []string{"93.184.216.34"})
	if err != nil {
		t.Fatalf("expected public IP to be allowed, got: %v", err)
	}
}

func TestIsNetworkAllowedBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	err := p.IsNetworkAllowed(context.Background(), []string{"192.168.1.1"})
	if err == nil {
		t.Fatal("expected private IP to be blocked")
	}
}
