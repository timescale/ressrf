package ressrfstatic

import (
	"fmt"

	"github.com/timescale/ressrf/go/ressrf-static/cloudmod"
)

// CloudModule is the canonical alias for the cloud-provider value type.
// The concrete definition lives in package cloudmod so the cloud/*
// sub-packages can construct CloudModules without importing the main
// package (which would create an import cycle with the main package's
// own test files that use the providers).
//
// Construct via the helpers in
// github.com/timescale/ressrf/go/ressrf-static/cloud/{aws,azure,gcp} and
// pass to PolicyBuilder.WithCloudModule.
type CloudModule = cloudmod.Module

// applyCloudModule parses a module's JSON and appends its deny CIDRs to
// the policy's deny set. Matches the WASM ABI surface (deny-CIDRs-only).
//
// Domain-level suffixes (DeniedDomainSuffixes / ServiceDomainSuffixes)
// are NOT applied automatically — they're an opt-in via the suffix
// accessors on each provider sub-package, piped through
// PolicyBuilder.WithDeniedSuffixes / WithTrustedSuffixes. This keeps
// go/ressrf-static behaviourally identical to the WASM-backed go/ressrf
// for the parity gate in parity_test.go.
//
// The ServiceRanges field (per-service IP prefixes) is metadata used by
// audit "match_reason" strings in the Rust core; we don't surface it.
func applyCloudModule(m CloudModule, deny *CIDRSet) error {
	if len(m.JSON) == 0 {
		return fmt.Errorf("ressrfstatic: cloud module %q has empty JSON payload (did you call Module() with a nil package?)", m.Name)
	}
	c, err := ParseCloudFile(m.JSON)
	if err != nil {
		return fmt.Errorf("ressrfstatic: cloud module %q: %w", m.Name, err)
	}
	for _, r := range c.DenyRanges {
		cidr, perr := ParseCIDR(r.CIDR)
		if perr != nil {
			return fmt.Errorf("ressrfstatic: bad %s cloud CIDR %q: %w", m.Name, r.CIDR, perr)
		}
		deny.Add(cidr)
	}
	return nil
}
