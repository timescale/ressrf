package ressrfstatic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// insecureSSHConfig returns a ClientConfig wired with InsecureIgnoreHostKey.
// The SSH e2e tests only exercise the SSRF reject path so handshake details
// don't matter; centralizing the config keeps each test focused on the
// policy boundary.
func insecureSSHConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "ressrf-static-test",
		Auth:            []ssh.AuthMethod{ssh.Password("ignored")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func TestSSHDialBlocksPrivate(t *testing.T) {
	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	require.NoError(t, err)

	client, err := p.SSHDial(context.Background(), "10.0.0.1:22", insecureSSHConfig())
	require.Error(t, err, "dial to RFC1918 should be blocked")
	require.ErrorIs(t, err, ErrBlocked)
	require.Nil(t, client)
}

func TestSSHDialBlocksIMDS(t *testing.T) {
	p, err := NewPolicyBuilder(PresetExternalOnly).Build()
	require.NoError(t, err)

	client, err := p.SSHDial(context.Background(), "169.254.169.254:22", insecureSSHConfig())
	require.Error(t, err, "dial to IMDS should be blocked")
	require.ErrorIs(t, err, ErrBlocked)
	require.Nil(t, client)
}

func TestSSHDialEmitsConnectionAttempt(t *testing.T) {
	sink := &RecordingSink{}
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAuditSink(sink).
		Build()
	require.NoError(t, err)
	sink.Reset()

	_, err = p.SSHDial(context.Background(), "10.0.0.5:22", insecureSSHConfig())
	require.Error(t, err)

	var ce *ConnectionAttempt
	for _, e := range sink.Events {
		if got, ok := e.(*ConnectionAttempt); ok && got.Protocol == "ssh" {
			ce = got
			break
		}
	}
	require.NotNil(t, ce, "no ConnectionAttempt(ssh) event among %d events", len(sink.Events))
	require.False(t, ce.Allowed)
	require.Equal(t, "10.0.0.5:22", ce.RemoteAddr)
}
