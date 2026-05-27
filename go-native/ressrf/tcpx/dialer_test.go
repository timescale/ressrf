package tcpx_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/ressrftest"
	"github.com/timescale/ressrf/go-native/ressrf/tcpx"
)

func buildExternalPolicy(t *testing.T) *ressrf.Policy {
	t.Helper()
	p, err := ressrf.NewPolicy(ressrf.PresetExternalOnly,
		ressrf.WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSafeDialerBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	dialer := tcpx.Dialer(p, tcpx.WithDialTimeout(1*time.Second))
	if _, err := dialer.DialContext(context.Background(), "tcp", "10.0.0.1:80"); err == nil {
		t.Fatal("expected error dialing private IP, got nil")
	}
}

func TestSafeDialerBlocksLoopback(t *testing.T) {
	p := buildExternalPolicy(t)
	dialer := tcpx.Dialer(p, tcpx.WithDialTimeout(1*time.Second))
	if _, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:8080"); err == nil {
		t.Fatal("expected error dialing loopback, got nil")
	}
}

func TestSafeDialerBlocksLinkLocal(t *testing.T) {
	p := buildExternalPolicy(t)
	dialer := tcpx.Dialer(p, tcpx.WithDialTimeout(1*time.Second))
	if _, err := dialer.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil {
		t.Fatal("expected error dialing link-local IMDS, got nil")
	}
}

func TestDialContextRespectsDisableForTests(t *testing.T) {
	p := buildExternalPolicy(t)
	ressrftest.DisableForTests(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind localhost listener")
	}
	conn, err := tcpx.DialContext(context.Background(), p, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected success with disabled policy, got: %v", err)
	}
	_ = conn.Close()
}
