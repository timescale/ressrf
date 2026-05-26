package engine

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// FuzzPolicy mirrors fuzz/fuzz_targets/fuzz_policy.rs: build a policy from
// arbitrary deny/allow CIDR strings, evaluate arbitrary IPs, and check that
// the documented invariants still hold.
//
// The Go fuzz harness only supports a fixed parameter signature, so we pack
// (preset, denyCIDRs, allowCIDRs, IPs) into two delimited strings.
func FuzzPolicy(f *testing.F) {
	seeds := [][2]string{
		{"external_only|10.0.0.0/8;192.168.0.0/16|10.42.0.0/16", "10.42.1.1;10.0.0.1;8.8.8.8"},
		{"external_only||", "169.254.169.254;::1"},
		{"internal_only||203.0.113.0/24", "203.0.113.5;8.8.8.8"},
		{"none||", "10.0.0.1"},
		{"external_only|garbage//cidr;10.0.0.0/8|", "10.0.0.1"},
		{"external_only||0.0.0.0/0", "127.0.0.1;10.0.0.1"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, config, addrStrs string) {
		preset, denyCIDRs, allowCIDRs := parsePolicyConfig(config)
		policy, err := NewPolicyBuilder(preset).
			AddDeniedCIDRs(denyCIDRs).
			AddAllowedCIDRs(allowCIDRs).
			Build()
		if err != nil {
			// Bad CIDR strings are an expected fuzz outcome now; just skip.
			return
		}

		addrs := parseAddrs(addrStrs)

		// Two independent calls must agree (determinism).
		r1 := policy.IsNetworkAllowed(addrs)
		r2 := policy.IsNetworkAllowed(addrs)
		if (r1 == nil) != (r2 == nil) {
			t.Fatalf("non-deterministic policy: %v vs %v (config=%q ips=%q)", r1, r2, config, addrStrs)
		}

		// None preset must allow any non-empty IP list.
		if preset == PresetNone && len(addrs) > 0 && r1 != nil {
			t.Fatalf("PresetNone denied %v: %v", addrs, r1)
		}

		// Empty IP list must produce a DnsEmptyResponse reason.
		if len(addrs) == 0 {
			var reason *DnsEmptyResponse
			if !errors.As(r1, &reason) {
				t.Fatalf("empty IPs should yield DnsEmptyResponse, got %v", r1)
			}
		}

		// Round-trip through the string entry point must agree with the
		// netip.Addr one for IPs we successfully parsed.
		strInputs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			strInputs = append(strInputs, a.String())
		}
		rs := policy.IsNetworkAllowedStrings(strInputs)
		if (rs == nil) != (r1 == nil) {
			t.Fatalf("string/addr disagreement: addr=%v str=%v", r1, rs)
		}
	})
}

func parsePolicyConfig(s string) (Preset, []string, []string) {
	parts := strings.SplitN(s, "|", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	preset := PresetFromString(parts[0])
	deny := splitNonEmptySemi(parts[1])
	allow := splitNonEmptySemi(parts[2])
	return preset, deny, allow
}

func splitNonEmptySemi(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseAddrs(s string) []netip.Addr {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ";")
	out := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if a, err := netip.ParseAddr(p); err == nil {
			out = append(out, a)
		}
	}
	return out
}
