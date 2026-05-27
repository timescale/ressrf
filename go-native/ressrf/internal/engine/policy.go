package engine

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// Preset names the high-level policy mode. Mirrors crates/ressrf-core/src/policy.rs.
type Preset uint8

const (
	PresetNone Preset = iota
	PresetExternalOnly
	PresetInternalOnly
)

func (p Preset) String() string {
	switch p {
	case PresetNone:
		return "None"
	case PresetExternalOnly:
		return "ExternalOnly"
	case PresetInternalOnly:
		return "InternalOnly"
	}
	return "Unknown"
}

// PresetFromString accepts the snake_case names used by the public API and
// audit-event vectors ("external_only" etc.).
func PresetFromString(s string) Preset {
	switch strings.ToLower(s) {
	case "external_only", "externalonly":
		return PresetExternalOnly
	case "internal_only", "internalonly":
		return PresetInternalOnly
	default:
		return PresetNone
	}
}

// Policy is the immutable, concurrency-safe policy handle. The hot path
// (isNetworkAllowedIPs, isRequestAllowed) takes no locks because all fields
// are set once at build time.
type Policy struct {
	preset       Preset
	denySet      CIDRSet
	allowSet     CIDRSet
	cloudModules []string
	ruleset      URLRuleset
	validator    *URIValidator

	// sinkMu protects emission ordering; the sink itself can be nil for the
	// common "no audit" case, which is checked without the lock to avoid
	// contention.
	sink   AuditSink
	sinkMu sync.Mutex
}

type tieredCIDR struct {
	cidr string
	tier DataTier
}

// PolicyBuilder is a single-use builder. Build consumes its state into a
// finalized Policy; the builder must not be reused afterwards.
type PolicyBuilder struct {
	preset       Preset
	denyCIDRs    []tieredCIDR
	allowCIDRs   []string
	cloudModules []string
	ruleset      URLRuleset
	validator    *URIValidator
	sink         AuditSink
}

func NewPolicyBuilder(p Preset) *PolicyBuilder {
	return &PolicyBuilder{preset: p, validator: NewURIValidator()}
}

func (b *PolicyBuilder) AddDeniedCIDRs(cidrs []string) *PolicyBuilder {
	for _, c := range cidrs {
		b.denyCIDRs = append(b.denyCIDRs, tieredCIDR{cidr: c, tier: TierUserDeny})
	}
	return b
}

func (b *PolicyBuilder) AddAllowedCIDRs(cidrs []string) *PolicyBuilder {
	b.allowCIDRs = append(b.allowCIDRs, cidrs...)
	return b
}

// AddCloudProviderDenies adds each provider's defensive denies: metadata-endpoint
// IP CIDRs (e.g. 169.254.169.254/32, 169.254.170.2/32, fd00:ec2::254/128) AND
// internal DNS suffixes (e.g. .compute.internal, .internal.cloudapp.net,
// metadata.google.internal). Both flavours are additive denies; neither flips
// any validator mode. The provider is recorded in cloudModules.
//
// Mirrors crates/ressrf-core/src/policy.rs::with_cloud (IP side) plus the
// denied-suffix half of crates/.../uri_validator.rs::with_cloud_provider
// (DNS side). This is the option to use when the intent is "harden against
// this cloud's known internal endpoints".
func (b *PolicyBuilder) AddCloudProviderDenies(names ...string) *PolicyBuilder {
	for _, name := range names {
		name = strings.ToLower(name)
		ranges := CloudProviderDenyRanges(name)
		if ranges == nil {
			// Unknown provider: silently ignore, same as the Rust side.
			continue
		}
		b.cloudModules = append(b.cloudModules, name)
		tier := CloudProviderTier(name)
		for _, r := range ranges {
			b.denyCIDRs = append(b.denyCIDRs, tieredCIDR{cidr: r, tier: tier})
		}
		b.validator.AddDeniedSuffixes(CloudProviderDeniedSuffixes(name))
	}
	return b
}

// AddDeniedSuffixes appends host suffixes that the URI validator must reject.
// Matching is boundary-aware and case-insensitive (see domainMatchesSuffix).
// Additive only; does not change validator mode.
func (b *PolicyBuilder) AddDeniedSuffixes(suffixes ...string) *PolicyBuilder {
	b.validator.AddDeniedSuffixes(suffixes)
	return b
}

// AddDomainAllowList registers per-policy allow-list suffixes. Once any
// suffix is registered, non-IP hosts that don't match one are rejected with
// DomainNotInAllowList. The name says what the call does; for additive
// suffix denies without mode change, use AddDeniedSuffixes.
func (b *PolicyBuilder) AddDomainAllowList(suffixes ...string) *PolicyBuilder {
	b.validator.AddDomainAllowList(suffixes)
	return b
}

func (b *PolicyBuilder) AddURLAllow(rule URLRule) *PolicyBuilder {
	b.ruleset.Allow = append(b.ruleset.Allow, rule)
	return b
}

func (b *PolicyBuilder) AddURLDeny(rule URLRule) *PolicyBuilder {
	b.ruleset.Deny = append(b.ruleset.Deny, rule)
	return b
}

func (b *PolicyBuilder) SetAuditSink(sink AuditSink) *PolicyBuilder {
	b.sink = sink
	return b
}

// Build finalizes the policy. The returned *Policy is safe for concurrent use.
// Returns an error if any user-supplied CIDR string fails to parse: a typo in
// a deny entry would silently leave the policy permissive, which is exactly
// the failure mode this library exists to prevent.
func (b *PolicyBuilder) Build() (*Policy, error) {
	p := &Policy{
		preset:       b.preset,
		cloudModules: append([]string(nil), b.cloudModules...),
		ruleset:      b.ruleset,
		validator:    b.validator,
		sink:         b.sink,
	}

	if b.preset == PresetExternalOnly {
		p.denySet.Ranges = DefaultDenySet()
	}
	for _, entry := range b.denyCIDRs {
		c, err := ParseCIDRLoose(entry.cidr, entry.tier)
		if err != nil {
			return nil, fmt.Errorf("deny CIDR %q: %w", entry.cidr, err)
		}
		p.denySet.Add(c)
	}
	for _, s := range b.allowCIDRs {
		c, err := ParseCIDRLoose(s, TierUserAllow)
		if err != nil {
			return nil, fmt.Errorf("allow CIDR %q: %w", s, err)
		}
		p.allowSet.Add(c)
	}

	if p.sink != nil {
		p.emitAudit(AuditEvent{
			Kind: AuditPolicyCreated,
			Fields: map[string]any{
				"preset":        p.preset.String(),
				"cloud_modules": p.cloudModules,
				"deny_count":    p.denySet.Len(),
				"allow_count":   p.allowSet.Len(),
			},
		})
	}
	return p, nil
}

// Preset returns the preset this policy was built with.
func (p *Policy) Preset() Preset { return p.preset }

// IsNetworkAllowed validates that every IP in the list is permitted. Returns
// nil on success or a DenyReason (which implements error) on rejection.
// Behaviour matches crates/ressrf-core/src/policy.rs::is_network_allowed.
//
// Emits a HostValidated audit event on every call (if a sink is attached).
func (p *Policy) IsNetworkAllowed(ips []netip.Addr) error {
	if len(ips) == 0 {
		reason := &DNSEmptyResponse{}
		p.emitHostValidated(ips, reason)
		return reason
	}
	r := p.isNetworkAllowedIPs(ips)
	p.emitHostValidated(ips, r)
	if r != nil {
		return r
	}
	return nil
}

// isNetworkAllowedIPs is the non-public hot path shared with the URI validator.
// Returns a typed DenyReason or untyped nil — callers must not store the
// result in a DenyReason interface variable and then check `!= nil` against
// untyped nil; use the returned value directly.
func (p *Policy) isNetworkAllowedIPs(ips []netip.Addr) DenyReason {
	switch p.preset {
	case PresetNone:
		return nil
	case PresetInternalOnly:
		for _, ip := range ips {
			if p.allowSet.Contains(ip) == nil {
				return &NotInAllowList{Host: ip.String()}
			}
		}
		return nil
	case PresetExternalOnly:
		for _, ip := range ips {
			if p.allowSet.Contains(ip) != nil {
				continue
			}
			if matched := p.denySet.Contains(ip); matched != nil {
				return &InDenyCIDR{CIDR: matched.Original, Source: matched.Source}
			}
		}
		return nil
	}
	return nil
}

// IsNetworkAllowedStrings parses the provided IP strings and delegates to
// IsNetworkAllowed. Strings that fail to parse return a HostnameInvalid
// DenyReason.
func (p *Policy) IsNetworkAllowedStrings(ips []string) error {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return &HostnameInvalid{Detail: "cannot parse IP: " + s}
		}
		addrs = append(addrs, addr)
	}
	return p.IsNetworkAllowed(addrs)
}

// IsRequestAllowed runs URL rules then (unless bypassed) the URI validator and
// IP check. This is the public entry point invoked by Policy.IsAllowed.
//
// Emits a URLValidated audit event on every call (if a sink is attached).
func (p *Policy) IsRequestAllowed(url string) error {
	r := p.isRequestAllowed(url)
	p.emitURLValidated(url, r)
	if r != nil {
		return r
	}
	return nil
}

func (p *Policy) isRequestAllowed(url string) DenyReason {
	if !p.ruleset.IsEmpty() {
		switch p.ruleset.Evaluate(url) {
		case URLDenied:
			return &URLRuleDenied{URL: url}
		case URLAllowedBypassIP:
			return nil
		case URLAllowed, URLNoMatch:
			// continue to URI validation + IP check.
		}
	}
	return p.validator.validateURL(url, p)
}

// emitAudit forwards an event under sinkMu so concurrent callers serialize on
// the sink (matches the Rust behavior, which holds the sink behind &dyn).
func (p *Policy) emitAudit(event AuditEvent) {
	if p.sink == nil {
		return
	}
	p.sinkMu.Lock()
	p.sink.Emit(event)
	p.sinkMu.Unlock()
}

// emitHostValidated fires the host-level decision event. Skipped cheaply
// when no sink is attached.
func (p *Policy) emitHostValidated(ips []netip.Addr, reason DenyReason) {
	if p.sink == nil {
		return
	}
	ipStrs := make([]string, len(ips))
	for i, ip := range ips {
		ipStrs[i] = ip.String()
	}
	fields := map[string]any{
		"resolved_ips": ipStrs,
		"allowed":      reason == nil,
	}
	if reason != nil {
		fields["deny_kind"] = reason.Kind().String()
	}
	p.emitAudit(AuditEvent{Kind: AuditHostValidated, Fields: fields})
}

// emitURLValidated fires the URL-level decision event. Parses scheme + host
// from the URL on a best-effort basis (the validator already failed if these
// were malformed, so on the success path they're reliable).
func (p *Policy) emitURLValidated(url string, reason DenyReason) {
	if p.sink == nil {
		return
	}
	scheme, host, _ := splitURLComponents(url)
	fields := map[string]any{
		"url":     url,
		"scheme":  scheme,
		"host":    host,
		"allowed": reason == nil,
	}
	if reason != nil {
		fields["deny_kind"] = reason.Kind().String()
	}
	p.emitAudit(AuditEvent{Kind: AuditURLValidated, Fields: fields})
}
