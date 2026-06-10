package ressrf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/timescale/ressrf/go-native/ressrf/internal/engine"
)

// CloudProvider names a built-in cloud-metadata module. The exported package
// variables CloudAWS, CloudAzure, and CloudGCP are the only constructible
// values: the underlying field is unexported so external code cannot fabricate
// invalid providers, which removes the runtime "unknown provider" / typo /
// case-folding failure class entirely. Pass to WithCloudProviderDenies for
// per-provider metadata-endpoint deny ranges and internal-DNS suffix denies,
// or to CloudServiceSuffixes to seed NewAllowListPolicy with the provider's
// public service domains. For dynamic-config callers (CLI flag, env var,
// JSON), use ParseCloudProvider as the single string-to-CloudProvider
// boundary.
//
// The zero value (CloudProvider{}) is the only "invalid" state and is
// silently skipped by both WithCloudProviderDenies and CloudServiceSuffixes.
// Callers who care about misuse detection should construct via the exported
// vars or via ParseCloudProvider.
type CloudProvider struct{ s string }

// Built-in cloud providers. Names match the JSON config keys used by the
// upstream Rust core and every other binding. These are package vars (not
// consts) because struct literals cannot be const-expressible in Go.
var (
	CloudAWS   = CloudProvider{s: "aws"}
	CloudAzure = CloudProvider{s: "azure"}
	CloudGCP   = CloudProvider{s: "gcp"}
)

// Name returns the canonical lowercase identifier for the provider (e.g.
// "aws" for CloudAWS), matching the JSON config key. Returns "" for the
// zero value.
func (p CloudProvider) Name() string { return p.s }

// ParseCloudProvider returns the CloudProvider matching s (case-insensitive,
// trimmed). This is the only string-to-CloudProvider entry point and exists
// so dynamic-config callers (CLI flag, env var, JSON unmarshal) have one
// place where unknowns turn into ErrUnknownCloudProvider. Hard-coded call
// sites should use the exported vars directly.
func ParseCloudProvider(s string) (CloudProvider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "aws":
		return CloudAWS, nil
	case "azure":
		return CloudAzure, nil
	case "gcp":
		return CloudGCP, nil
	default:
		return CloudProvider{}, fmt.Errorf("%w: %q (known: aws, azure, gcp)", ErrUnknownCloudProvider, s)
	}
}

// Preset names a high-level policy configuration.
type Preset uint8

// Built-in policy presets.
const (
	// PresetNone is the zero value; all blocking is off. Audit sink still fires.
	PresetNone Preset = iota
	// PresetExternalOnly denies known internal / metadata ranges and allows
	// everything else. The most common production preset.
	PresetExternalOnly
	// PresetInternalOnly denies by default; every IP must be in the allow list.
	PresetInternalOnly
)

// String returns the preset's canonical name.
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

// URLRule defines a URL-level allow or deny matching rule. Construct via
// URLRuleGlob or URLRuleRegex; the bare struct is intentionally unexported
// so callers can't accidentally combine glob + regex semantics in one rule.
type URLRule struct {
	scheme        string
	host          string
	path          string
	regex         string
	bypassIPCheck bool
}

// URLRuleGlob matches a URL against scheme + host + path globs. An empty
// component matches anything. Host glob `*` matches a single DNS label;
// path glob `*` matches a single segment and `**` matches any depth.
func URLRuleGlob(scheme, host, path string) URLRule {
	return URLRule{scheme: scheme, host: host, path: path}
}

// URLRuleRegex matches the full URL against an RE2 pattern (Go regexp).
func URLRuleRegex(pattern string) URLRule {
	return URLRule{regex: pattern}
}

// WithBypassIPCheck marks an allow rule as bypassing the IP-level policy
// check. Has no effect on deny rules.
func (r URLRule) WithBypassIPCheck() URLRule {
	r.bypassIPCheck = true
	return r
}

// UnmarshalJSON lets URLRule be hydrated from the cross-language JSON test
// vectors (and any user-supplied config) without exposing the fields as a
// public surface. Schema mirrors the Rust UrlRule serde representation.
func (r *URLRule) UnmarshalJSON(data []byte) error {
	var wire struct {
		Scheme        string `json:"scheme,omitempty"`
		Host          string `json:"host,omitempty"`
		Path          string `json:"path,omitempty"`
		Regex         string `json:"regex,omitempty"`
		BypassIPCheck bool   `json:"bypass_ip_check,omitempty"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	r.scheme = wire.Scheme
	r.host = wire.Host
	r.path = wire.Path
	r.regex = wire.Regex
	r.bypassIPCheck = wire.BypassIPCheck
	return nil
}

// Policy is a compiled SSRF policy. It is safe for concurrent use; the
// internal engine handles its own synchronization.
type Policy struct {
	core *engine.Policy
}

// Option configures a Policy at construction time. Options are composable
// values (not methods on a builder), so they can be stored, reused, or
// passed around. See https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis
// for the pattern's rationale.
type Option func(*config)

type config struct {
	preset              Preset
	allowCIDRs          []string
	denyCIDRs           []string
	cloudProviderDenies []string
	deniedSuffixes      []string
	urlAllow            []URLRule
	urlDeny             []URLRule
	sink                AuditSink
}

// WithAllowedCIDRs adds CIDRs to the allow list (allow overrides deny).
// Multiple calls accumulate.
func WithAllowedCIDRs(cidrs ...string) Option {
	return func(c *config) { c.allowCIDRs = append(c.allowCIDRs, cidrs...) }
}

// WithDeniedCIDRs adds CIDRs to the deny list. Multiple calls accumulate.
func WithDeniedCIDRs(cidrs ...string) Option {
	return func(c *config) { c.denyCIDRs = append(c.denyCIDRs, cidrs...) }
}

// WithCloudProviderDenies adds each provider's defensive denies: the
// metadata-endpoint IP CIDRs (e.g. 169.254.169.254/32, AWS ECS at
// 169.254.170.2/32, IPv6 IMDSv2 at fd00:ec2::254/128) AND the per-provider
// internal DNS suffixes (e.g. .compute.internal, .internal.cloudapp.net,
// metadata.google.internal). Pure denies, no validator mode change.
//
// Use this when the intent is "harden against this cloud's known internal
// endpoints". For locking domain egress to a specific set of suffixes, use
// NewAllowListPolicy with CloudServiceSuffixes as the seed list.
func WithCloudProviderDenies(providers ...CloudProvider) Option {
	return func(c *config) {
		for _, p := range providers {
			if p.s == "" {
				continue // skip the zero value; see CloudProvider's doc
			}
			c.cloudProviderDenies = append(c.cloudProviderDenies, p.s)
		}
	}
}

// WithDeniedDomainSuffixes appends host suffixes the validator must reject.
// Matching is boundary-aware ("example.com" matches "api.example.com" but not
// "notexample.com") and case-insensitive. Additive only; does not change
// validator mode. Multiple calls accumulate. Valid for both NewPolicy and
// NewAllowListPolicy.
func WithDeniedDomainSuffixes(suffixes ...string) Option {
	return func(c *config) { c.deniedSuffixes = append(c.deniedSuffixes, suffixes...) }
}

// CloudServiceSuffixes returns the public service-domain suffixes for each
// listed provider (e.g. *.amazonaws.com for AWS, *.azurecr.io / *.windows.net
// for Azure, *.googleapis.com / *.appspot.com for GCP). The zero-value
// CloudProvider contributes nothing.
//
// Intended use is to seed NewAllowListPolicy when the intent is "lock egress
// to these clouds' service domains plus any additional explicit entries".
func CloudServiceSuffixes(providers ...CloudProvider) []string {
	var out []string
	for _, p := range providers {
		if p.s == "" {
			continue
		}
		out = append(out, engine.CloudProviderServiceSuffixes(p.s)...)
	}
	return out
}

// WithURLAllow adds a URL allow rule. Multiple calls accumulate.
func WithURLAllow(rule URLRule) Option {
	return func(c *config) { c.urlAllow = append(c.urlAllow, rule) }
}

// WithURLDeny adds a URL deny rule. Multiple calls accumulate.
func WithURLDeny(rule URLRule) Option {
	return func(c *config) { c.urlDeny = append(c.urlDeny, rule) }
}

// WithAuditSink attaches an audit sink. The last call wins.
func WithAuditSink(sink AuditSink) Option {
	return func(c *config) { c.sink = sink }
}

// NewPolicy compiles a deny-only Policy from the given preset and options.
// The URI validator is NOT in allow-list mode: non-IP hosts pass unless they
// match a denied suffix or fail the preset's IP-level checks. Returns an
// error if any user-supplied CIDR or URL-rule regex pattern is invalid.
//
// Allow-list mode is intentionally not reachable via Option here. To build
// an allow-list policy use NewAllowListPolicy, which takes the allowed
// suffixes as a required constructor parameter so the mode flip is visible
// at the call site rather than hidden in an options chain.
//
// Example:
//
//	policy, err := ressrf.NewPolicy(ressrf.PresetExternalOnly,
//	    ressrf.WithCloudProviderDenies(ressrf.CloudAWS, ressrf.CloudAzure, ressrf.CloudGCP),
//	    ressrf.WithAllowedCIDRs("10.42.0.0/16"),
//	    ressrf.WithURLAllow(ressrf.URLRuleGlob("https", "*.stripe.com", "/v1/**")),
//	)
func NewPolicy(preset Preset, opts ...Option) (*Policy, error) {
	return buildPolicy(preset, nil, opts)
}

// NewAllowListPolicy compiles a Policy with the URI validator in allow-list
// mode: non-IP hosts must match at least one of the supplied suffixes (or
// they're rejected with DomainNotInAllowList). The allowed list is required;
// an empty list would reject every non-IP host and is treated as a caller
// error. opts contribute the same way they do to NewPolicy (CIDR denies,
// denied suffixes, URL rules, audit sink, etc.). They layer additively on
// top of allow-list mode.
//
// Allow-list mode is a top-level construction choice rather than something
// an Option can flip. A code reviewer scanning a long options chain can
// trust that NewPolicy is deny-only and only NewAllowListPolicy locks
// egress. Use CloudServiceSuffixes to seed the allowed list with per-cloud
// service domains.
//
// Example:
//
//	policy, err := ressrf.NewAllowListPolicy(ressrf.PresetExternalOnly,
//	    ressrf.CloudServiceSuffixes(ressrf.CloudAWS),
//	    ressrf.WithCloudProviderDenies(ressrf.CloudAWS),
//	)
func NewAllowListPolicy(preset Preset, allowed []string, opts ...Option) (*Policy, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("%w: an empty allow-list would reject every non-IP host", ErrEmptyAllowList)
	}
	return buildPolicy(preset, allowed, opts)
}

// buildPolicy is the shared backend for NewPolicy / NewAllowListPolicy.
// allowList is nil for deny-only construction; non-empty for allow-list
// mode. The two public constructors are the only callers.
func buildPolicy(preset Preset, allowList []string, opts []Option) (*Policy, error) {
	switch preset {
	case PresetNone, PresetExternalOnly, PresetInternalOnly:
	default:
		// Without this an out-of-range value (bad cast, config parse, future
		// engine preset added before the public mapping catches up) would
		// silently hit presetToEngine's default branch and produce a
		// PresetNone (permit-all) policy.
		return nil, fmt.Errorf("%w: %d", ErrUnknownPreset, preset)
	}

	cfg := config{preset: preset}
	for _, opt := range opts {
		opt(&cfg)
	}

	core := engine.NewPolicyBuilder(presetToEngine(cfg.preset))
	core.AddAllowedCIDRs(cfg.allowCIDRs)
	core.AddDeniedCIDRs(cfg.denyCIDRs)
	core.AddCloudProviderDenies(cfg.cloudProviderDenies...)
	if len(cfg.deniedSuffixes) > 0 {
		core.AddDeniedSuffixes(cfg.deniedSuffixes...)
	}
	if len(allowList) > 0 {
		core.AddDomainAllowList(allowList...)
	}
	for _, rule := range cfg.urlAllow {
		compiled, err := engine.CompileURLRule(rule.scheme, rule.host, rule.path, rule.regex, rule.bypassIPCheck)
		if err != nil {
			return nil, fmt.Errorf("compile url allow rule: %w", err)
		}
		core.AddURLAllow(compiled)
	}
	for _, rule := range cfg.urlDeny {
		compiled, err := engine.CompileURLRule(rule.scheme, rule.host, rule.path, rule.regex, rule.bypassIPCheck)
		if err != nil {
			return nil, fmt.Errorf("compile url deny rule: %w", err)
		}
		core.AddURLDeny(compiled)
	}
	if cfg.sink != nil {
		core.SetAuditSink(&sinkAdapter{sink: cfg.sink})
	}
	corePolicy, err := core.Build()
	if err != nil {
		return nil, fmt.Errorf("build policy: %w", err)
	}
	return &Policy{core: corePolicy}, nil
}

func presetToEngine(p Preset) engine.Preset {
	switch p {
	case PresetExternalOnly:
		return engine.PresetExternalOnly
	case PresetInternalOnly:
		return engine.PresetInternalOnly
	default:
		return engine.PresetNone
	}
}

// IsAllowed checks whether a URL is permitted by the policy.
func (p *Policy) IsAllowed(_ context.Context, url string) error {
	if bypassed() {
		return nil
	}
	if err := p.core.IsRequestAllowed(url); err != nil {
		return toBlockedError(err, url, "")
	}
	return nil
}

// DeniedIPPrefixes returns the IP CIDR ranges this policy blocks at the network
// layer, in native form (IPv4 prefixes are Is4, not IPv4-mapped). For
// PresetExternalOnly this is the built-in default deny set plus any
// WithCloudProviderDenies and WithDeniedCIDRs entries; PresetNone and
// PresetInternalOnly return nil (they have no network-layer deny set).
//
// This exposes the same ranges IsNetworkAllowed enforces, so a caller that must
// mirror the gate at another layer — e.g. rendering a Kubernetes NetworkPolicy
// egress except-list — can derive it from the policy instead of hand-maintaining
// a parallel CIDR list that silently drifts. Bucket by family with
// Addr().Is4(); String() yields the canonical CIDR text (e.g. "10.0.0.0/8",
// "fc00::/7"). The allow set is not subtracted; see WithAllowedCIDRs.
func (p *Policy) DeniedIPPrefixes() []netip.Prefix {
	return p.core.DenyPrefixes()
}

// IsNetworkAllowed checks whether a set of IPs is permitted by the policy.
// This is the lower-level IP check (no URL parsing/scheme validation).
func (p *Policy) IsNetworkAllowed(_ context.Context, ips []string) error {
	if bypassed() {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return &BlockedError{Detail: "invalid IP: " + s, Host: s}
		}
		addrs = append(addrs, addr)
	}
	if err := p.core.IsNetworkAllowed(addrs); err != nil {
		return toBlockedError(err, "", "")
	}
	return nil
}

// IsNetworkAllowedAddrs is the netip.Addr-typed variant of IsNetworkAllowed,
// for callers (e.g. a net.Dialer.Control hook) that already have parsed
// addresses and want to skip the string round-trip.
func (p *Policy) IsNetworkAllowedAddrs(_ context.Context, addrs []netip.Addr) error {
	if bypassed() {
		return nil
	}
	if err := p.core.IsNetworkAllowed(addrs); err != nil {
		return toBlockedError(err, "", "")
	}
	return nil
}

// toBlockedError converts an engine error into a *BlockedError. If err
// resolves to a DenyReason via errors.As (covering both bare and
// fmt.Errorf("...%w...")-wrapped engine rejections), the typed reason is
// preserved so callers can type-switch on BlockedError.Reason. Otherwise
// we fall back to Detail so callers still receive a *BlockedError and
// errors.Is against ErrBlocked continues to hold.
func toBlockedError(err error, url, host string) *BlockedError {
	var reason DenyReason
	if errors.As(err, &reason) {
		return &BlockedError{Reason: reason, URL: url, Host: host}
	}
	return &BlockedError{Detail: err.Error(), URL: url, Host: host}
}

// sinkAdapter bridges engine.AuditSink to the public AuditSink. Events flow
// with a background context; callers wanting request-scoped context attach
// it to their own sink.
type sinkAdapter struct {
	sink AuditSink
}

func (s *sinkAdapter) Emit(event engine.AuditEvent) {
	fields, err := json.Marshal(event.Fields)
	if err != nil {
		// A field whose type doesn't round-trip through encoding/json (a chan,
		// a func, a value with a Marshaler that errors) used to produce an
		// empty payload here. Audit gaps are the failure mode this library
		// exists to prevent, so substitute a marker payload that names the
		// kind and the marshal error. The fallback marshal is over a
		// map[string]string and cannot itself fail.
		fields, _ = json.Marshal(map[string]string{
			"_marshal_error": err.Error(),
			"kind":           string(event.Kind),
		})
	}
	s.sink.Emit(context.Background(), &AuditEvent{Kind: string(event.Kind), Fields: fields})
}
