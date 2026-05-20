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
	// Sanity: IMDS IP must be present somewhere in the deny tiers (csp_metadata expected).
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

func TestLoadCloud(t *testing.T) {
	for _, name := range []string{"aws", "azure", "gcp"} {
		t.Run(name, func(t *testing.T) {
			c, err := LoadCloud(name)
			if err != nil {
				t.Fatalf("LoadCloud(%q): %v", name, err)
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

func TestLoadCloudUnknown(t *testing.T) {
	if _, err := LoadCloud("digitalocean"); err == nil {
		t.Errorf("expected error for unknown provider, got nil")
	}
}
