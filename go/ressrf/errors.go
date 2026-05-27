package ressrf

import (
	"errors"

	"github.com/timescale/ressrf/go/ressrf/internal/testbypass"
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

// Disabled returns true when SSRF protection is disabled (for testing).
// Production code outside this package has no way to flip the flag
// because the setter lives in the ressrftest subpackage and is gated
// on testing.TB.
func Disabled() bool {
	return testbypass.Flag.Load()
}
