package ressrfstatic

import (
	"sync/atomic"
	"testing"
)

// disabled is the process-wide off switch. Atomic for safe concurrent flips.
// Default off (= protection active).
var disabled atomic.Bool

// Disabled reports whether SSRF protection is bypassed. Used by the protocol
// adapters to short-circuit out to plain dialers, matching go/ressrf
// behavior so callers can swap imports cleanly.
func Disabled() bool {
	return disabled.Load()
}

// DisableForTests turns protection off for the duration of t. Auto-restores
// on test cleanup.
func DisableForTests(t testing.TB) {
	t.Helper()
	disabled.Store(true)
	t.Cleanup(func() { disabled.Store(false) })
}
