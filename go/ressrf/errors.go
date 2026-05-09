package ressrf

import (
	"errors"
	"sync/atomic"
	"testing"
)

// ErrBlocked is returned whenever a request is denied by the SSRF policy.
// Use errors.Is(err, ErrBlocked) to distinguish policy rejections from
// transient network errors.
var ErrBlocked = errors.New("ressrf: request blocked by SSRF policy")

// BlockedError wraps ErrBlocked with additional context about why the
// request was blocked.
type BlockedError struct {
	Reason string
	URL    string
}

func (e *BlockedError) Error() string {
	if e.Reason != "" {
		return "ressrf: blocked: " + e.Reason
	}
	return ErrBlocked.Error()
}

// Is reports whether target matches ErrBlocked.
func (e *BlockedError) Is(target error) bool {
	return target == ErrBlocked
}

func (e *BlockedError) Unwrap() error {
	return ErrBlocked
}

var disabled atomic.Bool

// Disabled returns true when SSRF protection is disabled (for testing).
func Disabled() bool {
	return disabled.Load()
}

// DisableForTests disables SSRF protection for the duration of a test.
// It automatically re-enables protection when the test completes.
func DisableForTests(t testing.TB) {
	t.Helper()
	disabled.Store(true)
	t.Cleanup(func() { disabled.Store(false) })
}
