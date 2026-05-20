package ressrfstatic

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialContextBlocksPrivate(t *testing.T) {
	// Spin up a real local listener; ExternalOnly should block the dial
	// because 127.0.0.1 is in the deny set.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", ln.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatalf("expected dial to be blocked")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("expected errors.Is(ErrBlocked), got %v", err)
	}
}

func TestDialContextAllowsAllowOverride(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected dial to succeed, got %v", err)
	}
	conn.Close()
}

func TestDialContextDisabledBypass(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		t.Fatal(err)
	}
	DisableForTests(t)

	conn, err := p.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected disabled bypass to succeed, got %v", err)
	}
	conn.Close()
}

func TestSafeDialerEmitsConnectionAttempt(t *testing.T) {
	sink := &RecordingSink{}
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("127.0.0.0/8").
		WithAuditSink(sink).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	sink.Reset()

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()

	conn, err := p.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	found := false
	for _, e := range sink.Events {
		if ce, ok := e.(*ConnectionAttempt); ok && ce.Protocol == "tcp" && ce.Allowed {
			found = true
			if !strings.Contains(ce.RemoteAddr, "127.0.0.1") {
				t.Errorf("remote_addr = %q, expected to contain 127.0.0.1", ce.RemoteAddr)
			}
			break
		}
	}
	if !found {
		t.Errorf("no allowed ConnectionAttempt(tcp) event among %d events", len(sink.Events))
	}
}
