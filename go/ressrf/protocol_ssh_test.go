package ressrf

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHDialBlocksPrivateIP(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	config := &ssh.ClientConfig{
		Timeout: 1 * time.Second,
	}

	_, err := p.SSHDial(context.Background(), "10.0.0.1:22", config)
	if err == nil {
		t.Fatal("expected blocked error for private SSH target")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestSSHDialBlocksLoopback(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	config := &ssh.ClientConfig{
		Timeout: 1 * time.Second,
	}

	_, err := p.SSHDial(context.Background(), "127.0.0.1:22", config)
	if err == nil {
		t.Fatal("expected blocked error for loopback SSH target")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestSSHDialBlocksIMDS(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	config := &ssh.ClientConfig{
		Timeout: 1 * time.Second,
	}

	_, err := p.SSHDial(context.Background(), "169.254.169.254:22", config)
	if err == nil {
		t.Fatal("expected blocked error for IMDS SSH target")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}

func TestSSHDialDefaultPort(t *testing.T) {
	p := buildExternalPolicy(t)
	defer func() { _ = p.Close(context.Background()) }()

	config := &ssh.ClientConfig{
		Timeout: 1 * time.Second,
	}

	_, err := p.SSHDial(context.Background(), "10.0.0.1", config)
	if err == nil {
		t.Fatal("expected blocked error for private target without explicit port")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected ErrBlocked, got: %v", err)
	}
}
