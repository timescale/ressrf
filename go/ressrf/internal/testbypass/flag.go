// Package testbypass holds the atomic flag that toggles SSRF enforcement
// off for tests. Splitting the consumer (ressrf, testing-free) from the
// producer (ressrftest, which imports testing) keeps flag parsing and
// benchmark scaffolding out of every consumer's production binary.
package testbypass

import "sync/atomic"

// Flag is the package-global bypass switch. Adapters in ressrf read it
// via Load to short-circuit the policy check. ressrftest.DisableForTests
// writes it (and registers a Cleanup that resets it) while a test runs.
var Flag atomic.Bool
