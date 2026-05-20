package ressrfstatic

import "fmt"

// applyCloudModule loads the embedded data for `name` and appends only its
// deny CIDRs to the policy.
//
// This matches the WASM ABI surface (crates/ressrf-wasm/src/lib.rs calls
// builder.with_cloud(provider) which is deny-CIDRs-only). The domain-level
// suffixes (DeniedDomainSuffixes / ServiceDomainSuffixes) are NOT applied
// automatically — they're an opt-in via PolicyBuilder.WithDeniedSuffixes /
// WithTrustedSuffixes. This keeps go/ressrf-static behaviourally identical
// to the WASM-backed go/ressrf for the parity gate in Task 12.
//
// The ServiceRanges field (per-service IP prefixes) is metadata used by
// audit "match_reason" strings in the Rust core; we don't surface it.
func applyCloudModule(name string, deny *CIDRSet, _ *URIValidator) error {
	c, err := LoadCloud(name)
	if err != nil {
		return err
	}
	for _, r := range c.DenyRanges {
		cidr, err := ParseCIDR(r.CIDR)
		if err != nil {
			return fmt.Errorf("ressrfstatic: bad %s cloud CIDR %q: %w", name, r.CIDR, err)
		}
		deny.Add(cidr)
	}
	return nil
}

// CloudDeniedSuffixesFor returns the denied domain suffix list for a cloud
// provider. Callers who want domain-level denial for cloud internal DNS can
// pipe this into PolicyBuilder.WithDeniedSuffixes:
//
//	suffixes, _ := ressrfstatic.CloudDeniedSuffixesFor("aws")
//	b.WithCloudProviders("aws").WithDeniedSuffixes(suffixes...)
func CloudDeniedSuffixesFor(name string) ([]string, error) {
	c, err := LoadCloud(name)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(c.DeniedDomainSuffixes))
	copy(out, c.DeniedDomainSuffixes)
	return out, nil
}

// CloudServiceSuffixesFor returns the legitimate-service suffix list for a
// cloud provider (e.g. ".amazonaws.com"). Pair with WithTrustedSuffixes to
// opt into strict trusted-suffix allowlisting.
func CloudServiceSuffixesFor(name string) ([]string, error) {
	c, err := LoadCloud(name)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(c.ServiceDomainSuffixes))
	copy(out, c.ServiceDomainSuffixes)
	return out, nil
}
