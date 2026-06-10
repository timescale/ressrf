package ressrf

import (
	"context"
	"slices"
	"testing"
)

func TestDeniedIPPrefixes(t *testing.T) {
	policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudAWS))
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	prefixes := policy.DeniedIPPrefixes()
	if len(prefixes) == 0 {
		t.Fatal("expected a non-empty deny set for PresetExternalOnly")
	}

	// Well-known ranges are present in canonical, family-native form.
	got := make([]string, len(prefixes))
	for i, p := range prefixes {
		got[i] = p.String()
	}
	for _, want := range []string{
		"10.0.0.0/8",         // RFC1918
		"169.254.0.0/16",     // link-local
		"169.254.169.254/32", // cloud IMDS (via CloudAWS)
		"fc00::/7",           // IPv6 ULA
		"::1/128",            // IPv6 loopback
	} {
		if !slices.Contains(got, want) {
			t.Errorf("deny set missing %s; got %v", want, got)
		}
	}

	// The exported list must agree with what the gate actually enforces: the
	// network address of every returned range is denied by IsNetworkAllowed, and
	// a public address is allowed. This invariant is what lets a consumer mirror
	// the gate (e.g. a NetworkPolicy except-list) without the two drifting apart.
	for _, p := range prefixes {
		ip := p.Addr().String()
		if err := policy.IsNetworkAllowed(context.Background(), []string{ip}); err == nil {
			t.Errorf("IsNetworkAllowed permitted %s, but it is in the exported deny set", ip)
		}
	}
	if err := policy.IsNetworkAllowed(context.Background(), []string{"1.1.1.1"}); err != nil {
		t.Errorf("expected public IP 1.1.1.1 to be allowed, got %v", err)
	}

	// PresetNone has no network-layer deny set.
	none, err := NewPolicy(PresetNone)
	if err != nil {
		t.Fatalf("NewPolicy(PresetNone): %v", err)
	}
	if got := none.DeniedIPPrefixes(); got != nil {
		t.Errorf("PresetNone should have no deny prefixes, got %v", got)
	}
}
