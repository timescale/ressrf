package sshx_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/timescale/ressrf/go-native/ressrf"
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
