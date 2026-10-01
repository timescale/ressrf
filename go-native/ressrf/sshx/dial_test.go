package sshx_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/ressrftest"
	"github.com/timescale/ressrf/go-native/ressrf/sshx"
	"golang.org/x/crypto/ssh"
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

func TestSSHDialBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	config := &ssh.ClientConfig{Timeout: 1 * time.Second}
	if _, err := sshx.Dial(context.Background(), p, "10.0.0.1:22", config); err == nil {
		t.Fatal("expected blocked error for private SSH target")
	} else if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestSSHDialBlocksLoopback(t *testing.T) {
	p := buildExternalPolicy(t)
	config := &ssh.ClientConfig{Timeout: 1 * time.Second}
	if _, err := sshx.Dial(context.Background(), p, "127.0.0.1:22", config); err == nil {
		t.Fatal("expected blocked error for loopback SSH target")
	} else if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestSSHDialBlocksIMDS(t *testing.T) {
	p := buildExternalPolicy(t)
	config := &ssh.ClientConfig{Timeout: 1 * time.Second}
	if _, err := sshx.Dial(context.Background(), p, "169.254.169.254:22", config); err == nil {
		t.Fatal("expected blocked error for IMDS SSH target")
	} else if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestSSHDialDefaultPort(t *testing.T) {
	p := buildExternalPolicy(t)
	config := &ssh.ClientConfig{Timeout: 1 * time.Second}
	if _, err := sshx.Dial(context.Background(), p, "10.0.0.1", config); err == nil {
		t.Fatal("expected blocked error for private target without explicit port")
	} else if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

// holdingListener accepts TCP connections and never answers, so an SSH
// client stalls in the handshake waiting for the server version banner.
func holdingListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
		}
	}()
	return ln.Addr().String()
}

func nonePolicy(t *testing.T) *ressrf.Policy {
	t.Helper()
	p, err := ressrf.NewPolicy(ressrf.PresetNone)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSSHDialHandshakeBoundedByTimeout pins config.Timeout as the bound on
// a stalled handshake when ctx carries no deadline. It cannot pin the
// total-budget property (a slow connect leaving less for the handshake):
// the local connect is instant, and tcpx.Dialer offers no hook to slow it.
func TestSSHDialHandshakeBoundedByTimeout(t *testing.T) {
	addr := holdingListener(t)
	config := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 500 * time.Millisecond}

	start := time.Now()
	_, err := sshx.Dial(context.Background(), nonePolicy(t), addr, config)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected handshake timeout against a holding server")
	}
	if elapsed > time.Second {
		t.Fatalf("handshake overran Timeout: took %v with Timeout=500ms", elapsed)
	}
}

// TestSSHDialAbortsOnCancellation pins cancellation without a deadline:
// ssh.NewClientConn ignores ctx, so a canceled caller must get ctx.Err()
// promptly instead of waiting for the handshake deadline.
func TestSSHDialAbortsOnCancellation(t *testing.T) {
	addr := holdingListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	config := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second}

	start := time.Now()
	_, err := sshx.Dial(ctx, nonePolicy(t), addr, config)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dial did not abort promptly on cancellation: took %v with Timeout=10s", elapsed)
	}
}

// TestSSHDialCtxDeadlineReportsCtxErr pins the error class at ctx expiry: it
// must always be ctx.Err(), never the conn deadline's i/o timeout. Folding
// the ctx deadline into the conn deadline made the two timers race, and
// about 1 run in 10 reported an i/o timeout; the loop makes a regression
// fail reliably.
func TestSSHDialCtxDeadlineReportsCtxErr(t *testing.T) {
	addr := holdingListener(t)
	p := nonePolicy(t)
	config := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second}

	for i := range 40 {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		_, err := sshx.Dial(ctx, p, addr, config)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("run %d: expected context.DeadlineExceeded, got: %v", i, err)
		}
	}
}

// TestSSHDialBypassHonorsCtx pins that ressrftest.DisableForTests only
// disables SSRF enforcement: the dial keeps the ctx contract, and a nil
// policy is safe under the bypass. The old bypass path called ssh.Dial,
// whose handshake has no deadline at all, so a regression hangs; the
// select turns that into a clean failure.
func TestSSHDialBypassHonorsCtx(t *testing.T) {
	ressrftest.DisableForTests(t)
	addr := holdingListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	config := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second}

	done := make(chan error, 1)
	go func() {
		_, err := sshx.Dial(ctx, nil, addr, config)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded under bypass, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial under bypass ignored ctx and hung")
	}
}

// TestSSHDialNilConfig pins the nil-config guard. The target accepts, so
// without the guard the dial reaches ssh.NewClientConn and panics on the
// nil dereference instead of returning an error.
func TestSSHDialNilConfig(t *testing.T) {
	if _, err := sshx.Dial(context.Background(), nonePolicy(t), holdingListener(t), nil); err == nil {
		t.Fatal("expected an error for a nil config")
	}
}

// TestSSHDialBracketedIPv6WithoutPort regresses the case where
// net.SplitHostPort fails on a bracketed IPv6 literal missing the
// port, and the fallback used to set host=addr literally. Combined
// with net.JoinHostPort that produced "[[::1]]:22" — doubly-bracketed
// and unparseable. The fix strips enclosing brackets so the policy
// check sees the bare IP and ErrBlocked surfaces cleanly.
func TestSSHDialBracketedIPv6WithoutPort(t *testing.T) {
	p := buildExternalPolicy(t)
	config := &ssh.ClientConfig{Timeout: 1 * time.Second}
	if _, err := sshx.Dial(context.Background(), p, "[::1]", config); err == nil {
		t.Fatal("expected blocked error for bracketed IPv6 loopback without port")
	} else if !errors.Is(err, ressrf.ErrBlocked) {
		t.Fatalf("expected ErrBlocked (not a parser-malformed-address error), got: %v", err)
	}
}
