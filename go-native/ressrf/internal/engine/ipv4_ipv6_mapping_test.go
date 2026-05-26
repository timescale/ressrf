package engine

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/timescale/ressrf/go-native/ressrf/internal/testvectors"
)

// TestIPv4IPv6MappingVectors asserts that an IPv4 address and its
// ::ffff:X.X.X.X mapped form fall in (or out of) a given CIDR identically.
// Guards against an SSRF bypass class where the IPv4-mapped IPv6 form would
// otherwise sneak past a deny rule expressed in IPv4 CIDR notation.
func TestIPv4IPv6MappingVectors(t *testing.T) {
	data, err := testvectors.Read("ipv4_ipv6_mapping.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			Name          string `json:"name"`
			IPv4          string `json:"ipv4"`
			IPv6Mapped    string `json:"ipv6_mapped"`
			CIDR          string `json:"cidr"`
			BothContained bool   `json:"both_contained"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			cidr, err := ParseCIDR(tc.CIDR, TierIana)
			if err != nil {
				t.Fatalf("parse cidr %q: %v", tc.CIDR, err)
			}
			v4, err := netip.ParseAddr(tc.IPv4)
			if err != nil {
				t.Fatalf("parse ipv4 %q: %v", tc.IPv4, err)
			}
			v6, err := netip.ParseAddr(tc.IPv6Mapped)
			if err != nil {
				t.Fatalf("parse ipv6_mapped %q: %v", tc.IPv6Mapped, err)
			}
			gotV4 := cidr.Contains(v4)
			gotV6 := cidr.Contains(v6)
			if gotV4 != tc.BothContained || gotV6 != tc.BothContained {
				t.Errorf("Contains mismatch: cidr=%q v4=%q->%v v6=%q->%v, want both=%v",
					tc.CIDR, tc.IPv4, gotV4, tc.IPv6Mapped, gotV6, tc.BothContained)
			}
		})
	}
}
