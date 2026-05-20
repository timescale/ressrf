package ressrfstatic

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHDialBlocksPrivate(t *testing.T) {
	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{
		User:            "noone",
		Auth:            []ssh.AuthMethod{ssh.Password("nope")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err = p.SSHDial(context.Background(), "10.0.0.1:22", cfg)
	if err == nil {
		t.Fatal("expected SSHDial to be blocked")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("expected errors.Is(ErrBlocked), got %v", err)
	}
}

func TestSSHDialBlocksIMDS(t *testing.T) {
	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	_, err = p.SSHDial(context.Background(), "169.254.169.254:22", cfg)
	if err == nil {
		t.Fatal("expected SSHDial to be blocked")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("expected errors.Is(ErrBlocked), got %v", err)
	}
}

func TestSSHDialEmitsConnectionAttempt(t *testing.T) {
	sink := &RecordingSink{}
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAuditSink(sink).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	sink.Reset()

	_, _ = p.SSHDial(context.Background(), "10.0.0.5:22", cfg)

	found := false
	for _, e := range sink.Events {
		if ce, ok := e.(*ConnectionAttempt); ok && ce.Protocol == "ssh" && !ce.Allowed {
			found = true
			if ce.RemoteAddr != "10.0.0.5:22" {
				t.Errorf("RemoteAddr = %q, want %q", ce.RemoteAddr, "10.0.0.5:22")
			}
			break
		}
	}
	if !found {
		t.Errorf("no blocked ConnectionAttempt(ssh) in %d events", len(sink.Events))
	}
}
