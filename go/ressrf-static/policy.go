package ressrfstatic

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

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

// Policy is a compiled, immutable SSRF policy. Safe for concurrent use.
//
// Build instances via PolicyBuilder; call Policy.IsAllowed for URL-level
// checks or Policy.IsNetworkAllowed for IP-level checks.
type Policy struct {
	preset    Preset
	denySet   *CIDRSet
	allowSet  *CIDRSet
	urlRules  URLRuleset
	validator *URIValidator
	cloudMods []string // recorded for audit / introspection

	// Audit sink (Task 8) is wired in at Build time. Nil = no emission.
	auditSink AuditSink
}

// PolicyBuilder constructs an immutable Policy. Mirrors the fluent API
// of go/ressrf/policy.go::PolicyBuilder so callers can swap imports.
type PolicyBuilder struct {
	preset         Preset
	allowedCIDRs   []string
	deniedCIDRs    []string
	cloudProviders []string
	urlRules       URLRuleset
	auditSink      AuditSink

	// extension hooks: lets advanced callers attach extra trusted/denied
	// suffixes beyond what cloud modules contribute.
	extraTrustedSuffixes []string
	extraDeniedSuffixes  []string
}

// NewPolicyBuilder starts a builder from the given preset.
func NewPolicyBuilder(p Preset) *PolicyBuilder {
	return &PolicyBuilder{preset: p}
}

// WithAllowedCIDRs adds CIDRs to the allow list. Allow overrides deny.
// Uses loose parsing (auto-masks host bits).
func (b *PolicyBuilder) WithAllowedCIDRs(cidrs ...string) *PolicyBuilder {
	b.allowedCIDRs = append(b.allowedCIDRs, cidrs...)
	return b
}

// WithDeniedCIDRs adds CIDRs to the deny list. Uses loose parsing.
func (b *PolicyBuilder) WithDeniedCIDRs(cidrs ...string) *PolicyBuilder {
	b.deniedCIDRs = append(b.deniedCIDRs, cidrs...)
	return b
}

// WithCloudProviders attaches cloud-provider deny + suffix data.
// Valid names: "aws", "azure", "gcp". Unknown names cause Build() to fail.
func (b *PolicyBuilder) WithCloudProviders(providers ...string) *PolicyBuilder {
	b.cloudProviders = append(b.cloudProviders, providers...)
	return b
}

// WithURLAllow adds a URL-level allow rule.
func (b *PolicyBuilder) WithURLAllow(r URLRule) *PolicyBuilder {
	b.urlRules.Allow = append(b.urlRules.Allow, r)
	return b
}

// WithURLDeny adds a URL-level deny rule.
func (b *PolicyBuilder) WithURLDeny(r URLRule) *PolicyBuilder {
	b.urlRules.Deny = append(b.urlRules.Deny, r)
	return b
}

// WithURLRuleset replaces the entire URL ruleset (used by conformance vectors
// that ship a complete ruleset as JSON).
func (b *PolicyBuilder) WithURLRuleset(rs URLRuleset) *PolicyBuilder {
	b.urlRules = rs
	return b
}

// WithAuditSink attaches an audit sink. Emits events at decision points.
func (b *PolicyBuilder) WithAuditSink(s AuditSink) *PolicyBuilder {
	b.auditSink = s
	return b
}

// WithTrustedSuffixes adds extra trusted domain suffixes beyond what cloud
// modules contribute.
func (b *PolicyBuilder) WithTrustedSuffixes(suffixes ...string) *PolicyBuilder {
	b.extraTrustedSuffixes = append(b.extraTrustedSuffixes, suffixes...)
	return b
}

// WithDeniedSuffixes adds extra denied domain suffixes.
func (b *PolicyBuilder) WithDeniedSuffixes(suffixes ...string) *PolicyBuilder {
	b.extraDeniedSuffixes = append(b.extraDeniedSuffixes, suffixes...)
	return b
}

// Build compiles the policy. Returns an error if any CIDR is malformed, any
// URL regex fails to compile, or any cloud provider name is unknown.
func (b *PolicyBuilder) Build() (*Policy, error) {
	deny := NewCIDRSet()
	allow := NewCIDRSet()
	validator := NewURIValidator()

	// Preset baseline: ExternalOnly loads the embedded IANA + IPv6 override +
	// CSP metadata deny tiers. InternalOnly and None start empty.
	if b.preset == PresetExternalOnly {
		ranges, err := LoadIPRanges()
		if err != nil {
			return nil, err
		}
		for _, tier := range []Tier{ranges.Tiers.IANAIPv4, ranges.Tiers.IANAIPv6, ranges.Tiers.Override, ranges.Tiers.CSPMetadata} {
			for _, e := range tier.Entries {
				c, err := ParseCIDR(e.CIDR)
				if err != nil {
					return nil, fmt.Errorf("ressrfstatic: bad embedded CIDR %q in %s preset: %w", e.CIDR, b.preset, err)
				}
				deny.Add(c)
			}
		}
	}

	// Cloud modules contribute deny CIDRs + denied suffixes + trusted suffixes.
	for _, name := range b.cloudProviders {
		if err := applyCloudModule(name, deny, validator); err != nil {
			return nil, err
		}
	}

	// User-supplied allow/deny CIDRs (loose parsing — auto-mask host bits).
	for _, s := range b.deniedCIDRs {
		c, err := ParseCIDRLoose(s)
		if err != nil {
			return nil, fmt.Errorf("ressrfstatic: bad denied CIDR %q: %w", s, err)
		}
		deny.Add(c)
	}
	for _, s := range b.allowedCIDRs {
		c, err := ParseCIDRLoose(s)
		if err != nil {
			return nil, fmt.Errorf("ressrfstatic: bad allowed CIDR %q: %w", s, err)
		}
		allow.Add(c)
	}

	// Extra suffixes beyond cloud-supplied.
	if len(b.extraTrustedSuffixes) > 0 {
		validator.AddTrustedSuffixes(b.extraTrustedSuffixes...)
	}
	if len(b.extraDeniedSuffixes) > 0 {
		validator.AddDeniedSuffixes(b.extraDeniedSuffixes...)
	}

	// Compile URL rules (validates regex syntax).
	if err := b.urlRules.Compile(); err != nil {
		return nil, err
	}

	p := &Policy{
		preset:    b.preset,
		denySet:   deny,
		allowSet:  allow,
		urlRules:  b.urlRules,
		validator: validator,
		cloudMods: append([]string(nil), b.cloudProviders...),
		auditSink: b.auditSink,
	}
	if p.auditSink != nil {
		p.auditSink.Emit(&PolicyCreated{
			Preset:       string(p.preset),
			CloudModules: p.cloudMods,
			AllowCount:   allow.Len(),
			DenyCount:    deny.Len(),
		})
	}
	return p, nil
}

// NewExternalOnlyPolicy is a convenience shortcut for
// NewPolicyBuilder(PresetExternalOnly).Build(). Used by tests that pre-date
// the full builder.
func NewExternalOnlyPolicy() (*Policy, error) {
	return NewPolicyBuilder(PresetExternalOnly).Build()
}

// IsAllowed runs the full URL-level pipeline:
//  1. URL rules (deny first, then allow with optional BypassIPCheck).
//  2. URI structural validation + bare-IP policy check.
//
// Mirrors the WASM ABI ressrf_policy_is_request_allowed flow.
func (p *Policy) IsAllowed(ctx context.Context, rawURL string) error {
	// Step 1: URL rules.
	switch p.urlRules.Evaluate(rawURL) {
	case URLRuleDenied:
		err := &BlockedError{Reason: ReasonURLRuleDenied, URL: rawURL}
		p.emitURLValidated(rawURL, false, string(err.Reason), "")
		return err
	case URLRuleAllowedBypassIP:
		p.emitURLValidated(rawURL, true, "", "url_rule_allow_bypass_ip")
		return nil
	case URLRuleAllowed, URLRuleNoMatch:
		// Fall through to structural validation.
	}

	// Step 2: structural validation + bare-IP IP check.
	if err := p.validator.ValidateURL(rawURL, p); err != nil {
		matchReason := ""
		if be, ok := err.(*BlockedError); ok {
			matchReason = be.DetailText
		}
		p.emitURLValidated(rawURL, false, blockedReason(err), matchReason)
		return err
	}
	p.emitURLValidated(rawURL, true, "", "")
	return nil
}

// IsNetworkAllowed reports whether every given IP literal is permitted by
// the policy. Returns *BlockedError for the first denied IP.
//
// Preset semantics:
//   - InternalOnly: every IP must be in the allow set.
//   - ExternalOnly: allow set wins; otherwise reject if in deny set; else allow.
//   - None: only consult the deny set (user-supplied).
//
// Callers that have a hostname context (TCP dialer, HTTP transport) should
// prefer ValidateHost so the audit event includes the host.
func (p *Policy) IsNetworkAllowed(ips []string) error {
	return p.validateAddresses("", ips)
}

// ValidateHost is IsNetworkAllowed plus a host label. Audit events surface
// the host (and the resolved IPs) so operators can correlate by hostname.
func (p *Policy) ValidateHost(host string, ips []string) error {
	return p.validateAddresses(host, ips)
}

func (p *Policy) validateAddresses(host string, ips []string) error {
	if len(ips) == 0 {
		err := &BlockedError{Reason: ReasonDNSEmptyResponse, Host: host, DetailText: "DNS returned no addresses"}
		p.emitHostValidated(host, nil, false, string(err.Reason), "")
		return err
	}
	for _, ip := range ips {
		if err := p.checkOneIP(ip); err != nil {
			be := err.(*BlockedError)
			be.Host = host
			p.emitHostValidated(host, []string{ip}, false, string(be.Reason), be.DetailText)
			return be
		}
	}
	p.emitHostValidated(host, ips, true, "", "")
	return nil
}

func (p *Policy) checkOneIP(ip string) error {
	switch p.preset {
	case PresetInternalOnly:
		if p.allowSet.Contains(ip) != nil {
			return nil
		}
		return &BlockedError{Reason: ReasonIPNotInAllowList, IP: ip}
	case PresetExternalOnly:
		if p.allowSet.Contains(ip) != nil {
			return nil
		}
		if hit := p.denySet.Contains(ip); hit != nil {
			return &BlockedError{Reason: ReasonIPDeniedByCIDR, IP: ip, DetailText: hit.String()}
		}
		return nil
	case PresetNone:
		if hit := p.denySet.Contains(ip); hit != nil {
			return &BlockedError{Reason: ReasonIPDeniedByCIDR, IP: ip, DetailText: hit.String()}
		}
		return nil
	default:
		return fmt.Errorf("ressrfstatic: unknown preset %q", p.preset)
	}
}

// PresetName returns the policy's configured preset.
func (p *Policy) PresetName() Preset { return p.preset }

// CloudModules returns the list of cloud provider names this policy was
// built with.
func (p *Policy) CloudModules() []string {
	out := make([]string, len(p.cloudMods))
	copy(out, p.cloudMods)
	return out
}

// applyCloudModule is implemented in cloud.go. Declared here so policy.go
// stays self-contained even when cloud.go grows.

// emitURLValidated / emitHostValidated are no-ops when no audit sink is
// attached. They centralise the event-building logic so each decision point
// stays a one-liner.
func (p *Policy) emitURLValidated(rawURL string, allowed bool, reason, matchReason string) {
	if p.auditSink == nil {
		return
	}
	host, scheme := extractHostScheme(rawURL)
	p.auditSink.Emit(&URLValidated{URL: rawURL, Scheme: scheme, Host: host, Allowed: allowed, Reason: reason, MatchReason: matchReason})
}

func (p *Policy) emitHostValidated(host string, ips []string, allowed bool, reason, matchReason string) {
	if p.auditSink == nil {
		return
	}
	cp := make([]string, len(ips))
	copy(cp, ips)
	p.auditSink.Emit(&HostValidated{Host: host, ResolvedIPs: cp, Allowed: allowed, Reason: reason, MatchReason: matchReason})
}

// blockedReason extracts the reason string from an error. Returns the empty
// string if err is not a *BlockedError.
func blockedReason(err error) string {
	if be, ok := err.(*BlockedError); ok {
		return string(be.Reason)
	}
	return ""
}

// extractHostScheme parses the URL with net/url for audit metadata only.
// Failures are tolerated — audit shouldn't make a successful validation
// fail.
func extractHostScheme(rawURL string) (host, scheme string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	h := u.Hostname()
	s := strings.ToLower(u.Scheme)
	return h, s
}
