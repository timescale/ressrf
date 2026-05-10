package ressrf

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Preset defines a named policy configuration preset.
type Preset string

// Available policy presets.
const (
	PresetInternalOnly Preset = "InternalOnly"
	PresetExternalOnly Preset = "ExternalOnly"
	PresetNone         Preset = "None"
)

// URLRule defines a URL-level allow or deny matching rule.
// Fields are evaluated as follows: if Regex is set, it matches the entire URL
// and Scheme/Host/Path are ignored. Otherwise, Scheme is an exact match,
// Host is a glob pattern (* = single DNS label), and Path is a glob pattern
// (* = single segment, ** = any depth).
type URLRule struct {
	// Exact scheme match (e.g. "https"). Empty means any scheme.
	Scheme string `json:"scheme,omitempty"`
	// Host glob pattern (e.g. "*.stripe.com", "api.example.com").
	Host string `json:"host,omitempty"`
	// Path glob pattern (e.g. "/v1/**", "/api/*").
	Path string `json:"path,omitempty"`
	// Full regex matching the entire URL. When set, Scheme/Host/Path are ignored.
	Regex string `json:"regex,omitempty"`
	// When true on an allow rule, a matching URL skips the IP-level policy check.
	BypassIPCheck bool `json:"bypass_ip_check,omitempty"`
}

// urlRulesConfig is the JSON structure for url_rules in the WASM config.
type urlRulesConfig struct {
	Allow []URLRule `json:"allow,omitempty"`
	Deny  []URLRule `json:"deny,omitempty"`
}

// PolicyConfig matches the WASM ABI's PolicyConfig input struct.
type PolicyConfig struct {
	Preset         string          `json:"preset"`
	AllowCIDRs     []string        `json:"allow_cidrs,omitempty"`
	DenyCIDRs      []string        `json:"deny_cidrs,omitempty"`
	CloudProviders []string        `json:"cloud_providers,omitempty"`
	URLRules       *urlRulesConfig `json:"url_rules,omitempty"`
}

// Policy is a compiled SSRF policy backed by the WASM engine.
// It is safe for concurrent use.
type Policy struct {
	inst   *instance
	handle uint32
	mu     sync.Mutex
}

// PolicyBuilder constructs a Policy with the desired configuration.
type PolicyBuilder struct {
	config PolicyConfig
	sink   AuditSink
}

// NewPolicyBuilder creates a builder starting from the given preset.
func NewPolicyBuilder(preset Preset) *PolicyBuilder {
	return &PolicyBuilder{config: PolicyConfig{Preset: presetToWasm(preset)}}
}

func presetToWasm(p Preset) string {
	switch p {
	case PresetInternalOnly:
		return "internal_only"
	case PresetExternalOnly:
		return "external_only"
	case PresetNone:
		return "none"
	default:
		return "none"
	}
}

// WithAllowedCIDRs adds CIDRs to the allow list (overrides deny).
func (b *PolicyBuilder) WithAllowedCIDRs(cidrs ...string) *PolicyBuilder {
	b.config.AllowCIDRs = append(b.config.AllowCIDRs, cidrs...)
	return b
}

// WithDeniedCIDRs adds CIDRs to the deny list.
func (b *PolicyBuilder) WithDeniedCIDRs(cidrs ...string) *PolicyBuilder {
	b.config.DenyCIDRs = append(b.config.DenyCIDRs, cidrs...)
	return b
}

// WithCloudProviders adds cloud provider modules (e.g. "aws", "azure", "gcp")
// whose metadata endpoint IPs and internal domains will be denied.
func (b *PolicyBuilder) WithCloudProviders(providers ...string) *PolicyBuilder {
	b.config.CloudProviders = append(b.config.CloudProviders, providers...)
	return b
}

// WithURLAllow adds a URL allow rule to the policy.
func (b *PolicyBuilder) WithURLAllow(rule URLRule) *PolicyBuilder {
	if b.config.URLRules == nil {
		b.config.URLRules = &urlRulesConfig{}
	}
	b.config.URLRules.Allow = append(b.config.URLRules.Allow, rule)
	return b
}

// WithURLDeny adds a URL deny rule to the policy.
func (b *PolicyBuilder) WithURLDeny(rule URLRule) *PolicyBuilder {
	if b.config.URLRules == nil {
		b.config.URLRules = &urlRulesConfig{}
	}
	b.config.URLRules.Deny = append(b.config.URLRules.Deny, rule)
	return b
}

// WithAuditSink attaches an audit sink to receive policy events.
func (b *PolicyBuilder) WithAuditSink(sink AuditSink) *PolicyBuilder {
	b.sink = sink
	return b
}

// Build compiles the policy and returns a thread-safe Policy instance.
func (b *PolicyBuilder) Build(ctx context.Context) (*Policy, error) {
	inst, err := newInstance(ctx, b.sink)
	if err != nil {
		return nil, err
	}

	configJSON, err := json.Marshal(b.config)
	if err != nil {
		_ = inst.close(ctx)
		return nil, fmt.Errorf("ressrf: marshal config: %w", err)
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()

	ptr, err := inst.writeBytes(ctx, configJSON)
	if err != nil {
		_ = inst.close(ctx)
		return nil, err
	}

	// ressrf_policy_new returns a handle directly (u32::MAX on error).
	results, err := inst.create.Call(ctx, uint64(ptr), uint64(len(configJSON)))
	if err != nil {
		_ = inst.close(ctx)
		return nil, fmt.Errorf("ressrf: policy_new: %w", err)
	}

	handle := uint32(results[0])
	if handle == 0xFFFFFFFF {
		_ = inst.close(ctx)
		return nil, fmt.Errorf("ressrf: policy_new returned error (invalid config)")
	}

	return &Policy{inst: inst, handle: handle}, nil
}

// IsAllowed checks whether a URL is permitted by the policy.
func (p *Policy) IsAllowed(ctx context.Context, url string) error {
	if Disabled() {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// The WASM ABI: ressrf_policy_is_request_allowed(handle, json_ptr, json_len)
	// Input JSON: {"url": "..."}
	req, _ := json.Marshal(struct {
		URL string `json:"url"`
	}{URL: url})

	p.inst.mu.Lock()
	defer p.inst.mu.Unlock()

	ptr, err := p.inst.writeBytes(ctx, req)
	if err != nil {
		return err
	}

	results, err := p.inst.allowed.Call(ctx, uint64(p.handle), uint64(ptr), uint64(len(req)))
	if err != nil {
		return fmt.Errorf("ressrf: is_allowed: %w", err)
	}

	resultPtr := uint32(results[0])
	resultJSON, err := p.inst.readResult(ctx, resultPtr)
	if err != nil {
		return err
	}

	var res struct {
		Allowed bool   `json:"allowed"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(resultJSON, &res); err != nil {
		return fmt.Errorf("ressrf: unmarshal result: %w", err)
	}
	if !res.Allowed {
		return &BlockedError{Reason: res.Error, URL: url}
	}
	return nil
}

// IsNetworkAllowed checks whether a set of IPs is permitted by the policy.
// This is the lower-level IP check (no URL parsing/scheme validation).
func (p *Policy) IsNetworkAllowed(ctx context.Context, ips []string) error {
	if Disabled() {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	req, _ := json.Marshal(struct {
		IPs []string `json:"ips"`
	}{IPs: ips})

	p.inst.mu.Lock()
	defer p.inst.mu.Unlock()

	ptr, err := p.inst.writeBytes(ctx, req)
	if err != nil {
		return err
	}

	results, err := p.inst.networkAllowed.Call(ctx, uint64(p.handle), uint64(ptr), uint64(len(req)))
	if err != nil {
		return fmt.Errorf("ressrf: is_network_allowed: %w", err)
	}

	resultPtr := uint32(results[0])
	resultJSON, err := p.inst.readResult(ctx, resultPtr)
	if err != nil {
		return err
	}

	var res struct {
		Allowed bool   `json:"allowed"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(resultJSON, &res); err != nil {
		return fmt.Errorf("ressrf: unmarshal result: %w", err)
	}
	if !res.Allowed {
		return &BlockedError{Reason: res.Error, URL: ""}
	}
	return nil
}

// Close releases the WASM instance resources.
func (p *Policy) Close(ctx context.Context) error {
	return p.inst.close(ctx)
}
