package ressrfstatic

import (
	"context"
	"strings"
	"testing"
)

// policyDecisionCase mirrors the cases[] entries in policy_decisions.json.
// The vector tests IP-level decisions only (no URLs).
type policyDecisionCase struct {
	Name           string   `json:"name"`
	Preset         string   `json:"preset"`
	Allow          []string `json:"allow,omitempty"`
	CloudProviders []string `json:"cloud_providers,omitempty"`
	IPs            []string `json:"ips"`
	Expected       string   `json:"expected"` // "allowed" | "blocked"
	ReasonType     string   `json:"reason_type,omitempty"`
	Note           string   `json:"note,omitempty"`
}

func TestPolicyDecisionVectors(t *testing.T) {
	runVectors(t, policyDecisionsJSON,
		func(c policyDecisionCase) string { return c.Name },
		func(t *testing.T, c policyDecisionCase) {
			preset := parsePreset(t, c.Preset)
			b := NewPolicyBuilder(preset)
			if len(c.Allow) > 0 {
				b.WithAllowedCIDRs(c.Allow...)
			}
			if len(c.CloudProviders) > 0 {
				b.WithCloudProviders(c.CloudProviders...)
			}
			p, err := b.Build()
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			err = p.IsNetworkAllowed(c.IPs)
			switch c.Expected {
			case "allowed":
				if err != nil {
					t.Errorf("expected allowed, got %v", err)
				}
			case "blocked":
				if err == nil {
					t.Errorf("expected blocked (%s), got allowed", c.ReasonType)
				}
			default:
				t.Fatalf("unknown expected %q", c.Expected)
			}
		})
}

func parsePreset(t *testing.T, name string) Preset {
	t.Helper()
	switch strings.ToLower(name) {
	case "external_only":
		return PresetExternalOnly
	case "internal_only":
		return PresetInternalOnly
	case "none":
		return PresetNone
	default:
		t.Fatalf("unknown preset %q", name)
		return ""
	}
}

// TestPolicyIsAllowedOrchestration exercises the full URL-level pipeline:
// URL rules first (deny first, then allow with optional BypassIPCheck),
// then URI validator + bare-IP IP check.
//
// NOTE: two policies are used. Adding any allow rule turns the ruleset into
// "must match an allow", which fundamentally changes the deny behavior.
// See url_rules.go::Evaluate.
func TestPolicyIsAllowedOrchestration(t *testing.T) {
	ctx := context.Background()

	// Policy A: cloud (IP-level only, matching WASM behavior) + URL deny.
	// To get domain-level cloud denial as well, callers opt in via
	// WithDeniedSuffixes(CloudDeniedSuffixesFor("aws")...).
	awsSuffixes, err := CloudDeniedSuffixesFor("aws")
	if err != nil {
		t.Fatal(err)
	}
	pA, err := NewPolicyBuilder(PresetExternalOnly).
		WithCloudProviders("aws").
		WithDeniedSuffixes(awsSuffixes...).
		WithURLDeny(URLRule{Host: "*.evil.com"}).
		Build()
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	caseA := []struct {
		name    string
		url     string
		wantErr bool
		reason  DenyReason
	}{
		{"public_https_ok", "https://example.com/path", false, ""},
		{"imds_blocked", "http://169.254.169.254/latest/meta-data/", true, ""},
		{"url_rule_deny", "https://api.evil.com/x", true, ReasonURLRuleDenied},
		{"aws_internal_suffix_blocked", "http://foo.compute.internal/", true, ReasonDomainSuffixDenied},
		{"private_ip_blocked", "http://10.0.0.1/", true, ""},
		{"scheme_blocked", "ftp://example.com/", true, ReasonSchemeNotAllowed},
	}
	for _, c := range caseA {
		t.Run("A/"+c.name, func(t *testing.T) {
			err := pA.IsAllowed(ctx, c.url)
			if (err != nil) != c.wantErr {
				t.Fatalf("IsAllowed(%q) err=%v, wantErr=%v", c.url, err, c.wantErr)
			}
			if c.wantErr && c.reason != "" {
				if be, ok := err.(*BlockedError); !ok || be.Reason != c.reason {
					t.Errorf("reason = %v, want %v", err, c.reason)
				}
			}
		})
	}

	// Policy B: explicit allow + BypassIPCheck. Demonstrates that an
	// internal-IP URL can be allowed when the URL rule says so.
	pB, err := NewPolicyBuilder(PresetExternalOnly).
		WithURLAllow(URLRule{Scheme: "https", Host: "bypass.internal", BypassIPCheck: true}).
		Build()
	if err != nil {
		t.Fatalf("build B: %v", err)
	}
	caseB := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"bypass_match_ok", "https://bypass.internal/health", false},
		{"bypass_miss_denied_by_no_allow", "https://example.com/path", true},
	}
	for _, c := range caseB {
		t.Run("B/"+c.name, func(t *testing.T) {
			err := pB.IsAllowed(ctx, c.url)
			if (err != nil) != c.wantErr {
				t.Errorf("IsAllowed(%q) err=%v, wantErr=%v", c.url, err, c.wantErr)
			}
		})
	}
}

// TestPolicyAllowOverridesDeny: a user-supplied allow CIDR beats the
// preset's deny.
func TestPolicyAllowOverridesDeny(t *testing.T) {
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithAllowedCIDRs("10.0.0.0/24"). // override RFC1918 deny for one subnet
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.IsNetworkAllowed([]string{"10.0.0.5"}); err != nil {
		t.Errorf("10.0.0.5 should be allowed (in allow override): %v", err)
	}
	if err := p.IsNetworkAllowed([]string{"10.0.1.5"}); err == nil {
		t.Errorf("10.0.1.5 should still be blocked (outside override)")
	}
}

// TestPolicyInternalOnly: default-deny mode.
func TestPolicyInternalOnly(t *testing.T) {
	p, err := NewPolicyBuilder(PresetInternalOnly).
		WithAllowedCIDRs("192.168.0.0/16").
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.IsNetworkAllowed([]string{"192.168.1.1"}); err != nil {
		t.Errorf("192.168.1.1 should be allowed: %v", err)
	}
	if err := p.IsNetworkAllowed([]string{"8.8.8.8"}); err == nil {
		t.Errorf("8.8.8.8 should be denied (not in allow list)")
	}
}
