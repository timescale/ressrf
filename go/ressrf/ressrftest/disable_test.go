package ressrftest_test

import (
	"testing"

	"github.com/timescale/ressrf/go/ressrf"
	"github.com/timescale/ressrf/go/ressrf/ressrftest"
)

// TestDisableForTestsReEnablesAfterCleanup regresses the contract that
// the t.Cleanup registered by DisableForTests actually fires when the
// test exits. The nested-subtest shape is load-bearing: without it,
// the parent test's Cleanup would run after the assertion and the
// assertion would tell us nothing.
//
// A future refactor that drops the t.Cleanup line, swaps its order
// with Store(true), or otherwise breaks the re-enable would let
// bypass leak into every subsequent test in the same package — an
// order-dependent Heisenbug that's invisible until somebody reorders.
func TestDisableForTestsReEnablesAfterCleanup(t *testing.T) {
	if ressrf.Disabled() {
		t.Fatal("precondition: bypass should be off at test entry")
	}

	t.Run("disabled-during-subtest", func(t *testing.T) {
		ressrftest.DisableForTests(t)
		if !ressrf.Disabled() {
			t.Fatal("expected bypass active inside subtest")
		}
	})

	// Subtest has exited; t.Cleanup should have flipped Disabled back to false.
	if ressrf.Disabled() {
		t.Fatal("bypass leaked past subtest cleanup")
	}
}
