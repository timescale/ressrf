// Package ressrftest provides test-only helpers for ressrf consumers.
//
// DisableForTests lives here, not in ressrf itself, so the testing
// package (with its flag parsing and benchmark scaffolding) stays out of
// production binaries. Production code imports ressrf and never reaches
// testing; test code imports ressrftest explicitly.
package ressrftest

import (
	"testing"

	"github.com/timescale/ressrf/go-native/ressrf/internal/testbypass"
)

// DisableForTests disables SSRF protection for the duration of a test.
// It automatically re-enables protection when the test completes. This is
// the only way to bypass the engine and is intentionally gated on
// testing.TB so it can never be called from non-test code.
func DisableForTests(t testing.TB) {
	t.Helper()
	testbypass.Flag.Store(true)
	t.Cleanup(func() { testbypass.Flag.Store(false) })
}
