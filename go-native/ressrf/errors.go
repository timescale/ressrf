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

// ErrEmptyAllowList is returned by NewAllowListPolicy when the supplied
// allowed-suffix list is nil or empty. Exposed as a sentinel so callers
// can errors.Is-match the case (e.g. to special-case "operator forgot to
// wire the seed list" separately from other construction errors).
var ErrEmptyAllowList = errors.New("empty allow-list")

// ErrUnknownCloudProvider is returned by ParseCloudProvider when the input
// string does not name a built-in provider. WithCloudProviderDenies and
// CloudServiceSuffixes cannot produce this error because their CloudProvider
// parameter is structurally constrained to the exported package vars; the
// runtime check lives only at the string-parsing boundary.
var ErrUnknownCloudProvider = errors.New("unknown cloud provider")

// ErrUnknownPreset is returned by NewPolicy / NewAllowListPolicy when
// Preset is outside the documented set (PresetNone, PresetExternalOnly,
// PresetInternalOnly). Without this an unrecognised value silently
// mapped to PresetNone, producing a permit-all policy.
var ErrUnknownPreset = errors.New("unknown preset")

// BlockedError wraps ErrBlocked with structured context about why the request
// was blocked.
//
// Reason carries the typed engine rejection (one of the DenyReason variants:
// InDenyCIDR, SchemeNotAllowed, AmbiguousIPEncoding, ...). Use a type switch
// when category-specific fields are needed; use Reason.Kind() for purely
// categorical decisions. Reason may be nil if the block came from an adapter
// rather than the engine (rare: e.g. the redirect cap in httpx).
//
// Detail is the human-readable summary for cases where Reason is nil. URL
// and Host are populated when known by the adapter that constructed the
// error; they're high-cardinality and intentionally not part of Reason.
type BlockedError struct {
	Reason DenyReason // typed engine rejection, or nil for adapter-side blocks
	Detail string     // free-text summary used when Reason is nil
	URL    string     // full URL or address that triggered the block, if known
	Host   string     // host or IP that triggered the block, if known
}

func (e *BlockedError) Error() string {
	if e.Reason != nil {
		return "ressrf: blocked: " + e.Reason.Error()
	}
	if e.Detail != "" {
		return "ressrf: blocked: " + e.Detail
	}
	return ErrBlocked.Error()
}

// Kind returns the DenyKind tag of the underlying reason, or a zero DenyKind
// if no typed reason is present.
func (e *BlockedError) Kind() DenyKind {
	if e.Reason == nil {
		return 0
	}
	return e.Reason.Kind()
}

// Is reports whether target matches ErrBlocked.
func (e *BlockedError) Is(target error) bool {
	return target == ErrBlocked
}

func (e *BlockedError) Unwrap() error {
	return ErrBlocked
}

// bypassed reports whether SSRF protection has been disabled by a current
// test via DisableForTests. Hidden from the public API: production code
// must not have a way to toggle the engine off.
var testBypass atomic.Bool

// Bypassed reports whether SSRF protection is currently disabled by a test
// via DisableForTests. Adapters in httpx / tcpx / sshx call this for the
// early-return shortcut; production code outside this package has no way to
// flip the flag because the setter is gated on testing.TB.
func Bypassed() bool { return testBypass.Load() }

// bypassed is the package-internal alias kept for hot-path call sites.
var bypassed = testBypass.Load

// DisableForTests disables SSRF protection for the duration of a test.
// It automatically re-enables protection when the test completes. This is
// the only way to bypass the engine and is intentionally gated on
// testing.TB so it can never be called from non-test code.
func DisableForTests(t testing.TB) {
	t.Helper()
	testBypass.Store(true)
	t.Cleanup(func() { testBypass.Store(false) })
}
