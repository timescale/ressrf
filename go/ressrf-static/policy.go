package ressrfstatic

import "fmt"

// Preset selects the baseline deny/allow behavior. Mirrors
// crates/ressrf-core/src/policy.rs::Preset.
type Preset string

const (
	// PresetInternalOnly: default-deny; every destination must be in the allow set.
	PresetInternalOnly Preset = "InternalOnly"
	// PresetExternalOnly: deny known-bad ranges (IANA + IPv6 overrides + CSP metadata),
	// allow everything else.
	PresetExternalOnly Preset = "ExternalOnly"
	// PresetNone: no implicit deny or allow (audit-only mode).
	PresetNone Preset = "None"
)

// Policy is a compiled SSRF policy. Immutable after construction.
//
// NOTE: this is the minimal slice needed by the URI validator for bare-IP
// checks. Task 7 expands this with builder fluent API, URL rules, cloud
// modules, audit sink, and IsAllowed orchestration.
type Policy struct {
	preset   Preset
	denySet  *CIDRSet
	allowSet *CIDRSet
}

// NewExternalOnlyPolicy loads the embedded IANA + IPv6 override + CSP metadata
// deny ranges and returns a policy that allows everything else. This is the
// preset used by the cross-language url_validation conformance suite.
func NewExternalOnlyPolicy() (*Policy, error) {
	ranges, err := LoadIPRanges()
	if err != nil {
		return nil, err
	}
	deny := NewCIDRSet()
	for _, tier := range []Tier{ranges.Tiers.IANAIPv4, ranges.Tiers.IANAIPv6, ranges.Tiers.Override, ranges.Tiers.CSPMetadata} {
		for _, e := range tier.Entries {
			c, err := ParseCIDR(e.CIDR)
			if err != nil {
				return nil, fmt.Errorf("ressrfstatic: bad embedded CIDR %q: %w", e.CIDR, err)
			}
			deny.Add(c)
		}
	}
	return &Policy{preset: PresetExternalOnly, denySet: deny, allowSet: NewCIDRSet()}, nil
}

// IsNetworkAllowed reports whether every given IP literal is permitted by the
// policy. Returns *BlockedError for the first denied IP.
//
// The IPs are expected to be strict literals (the URI validator already
// rejects ambiguous IPv4 encodings via IsAmbiguousIP, and the TCP Control
// hook only ever passes a net.ParseIP-clean string).
func (p *Policy) IsNetworkAllowed(ips []string) error {
	for _, ip := range ips {
		if err := p.checkOneIP(ip); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) checkOneIP(ip string) error {
	switch p.preset {
	case PresetInternalOnly:
		// Default-deny: must be in allow set.
		if p.allowSet.Contains(ip) != nil {
			return nil
		}
		return &BlockedError{Reason: ReasonIPNotInAllowList, IP: ip}
	case PresetExternalOnly:
		// Allow override beats deny.
		if p.allowSet.Contains(ip) != nil {
			return nil
		}
		if hit := p.denySet.Contains(ip); hit != nil {
			return &BlockedError{Reason: ReasonIPDeniedByCIDR, IP: ip, DetailText: hit.String()}
		}
		return nil
	case PresetNone:
		// Audit-only: no implicit deny. Still consult the explicit deny set
		// (Task 7 may add user-supplied deny CIDRs here).
		if hit := p.denySet.Contains(ip); hit != nil {
			return &BlockedError{Reason: ReasonIPDeniedByCIDR, IP: ip, DetailText: hit.String()}
		}
		return nil
	default:
		return fmt.Errorf("ressrfstatic: unknown preset %q", p.preset)
	}
}

// Preset returns the policy's configured preset.
func (p *Policy) PresetName() Preset { return p.preset }
