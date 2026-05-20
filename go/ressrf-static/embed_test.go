package ressrfstatic

import "testing"

func TestLoadIPRanges(t *testing.T) {
	r, err := LoadIPRanges()
	if err != nil {
		t.Fatalf("LoadIPRanges: %v", err)
	}
	if got := len(r.Tiers.IANAIPv4.Entries); got == 0 {
		t.Errorf("IANA IPv4 tier empty")
	}
	if got := len(r.Tiers.IANAIPv6.Entries); got == 0 {
		t.Errorf("IANA IPv6 tier empty")
	}
	if got := len(r.Tiers.Override.Entries); got == 0 {
		t.Errorf("Override tier empty")
	}
	if got := len(r.Tiers.CSPMetadata.Entries); got == 0 {
		t.Errorf("CSP metadata tier empty")
	}
	// Sanity: IMDS IP must be present somewhere in the deny tiers
	// (csp_metadata expected).
	found := false
	for _, e := range r.Tiers.CSPMetadata.Entries {
		if e.CIDR == "169.254.169.254/32" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("IMDS CIDR 169.254.169.254/32 missing from csp_metadata tier")
	}
}

// TestParseCloudFile exercises ParseCloudFile against every supported
// provider's embedded JSON via the sub-packages. The sub-packages
// themselves carry the //go:embed; the main package only owns the
// parsing logic.
func TestParseCloudFile(t *testing.T) {
	for _, name := range []string{"aws", "azure", "gcp"} {
		t.Run(name, func(t *testing.T) {
			m := cloudModuleByName(t, name)
			c, err := ParseCloudFile(m.JSON)
			if err != nil {
				t.Fatalf("ParseCloudFile(%s): %v", name, err)
			}
			if c.Provider != name {
				t.Errorf("provider field = %q, want %q", c.Provider, name)
			}
			if len(c.DenyRanges) == 0 {
				t.Errorf("deny_ranges empty")
			}
			if len(c.ServiceDomainSuffixes) == 0 {
				t.Errorf("service_domain_suffixes empty")
			}
		})
	}
}

// TestCloudModuleEmptyJSON guards the friendly-error path in
// applyCloudModule for callers that construct a zero-value CloudModule.
func TestCloudModuleEmptyJSON(t *testing.T) {
	_, err := NewPolicyBuilder(PresetExternalOnly).
		WithCloudModule(CloudModule{Name: "broken"}).
		Build()
	if err == nil {
		t.Fatal("expected error for empty CloudModule JSON")
	}
}
