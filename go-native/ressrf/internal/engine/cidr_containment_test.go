package engine

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/timescale/ressrf/go-native/ressrf/internal/testvectors"
)

// TestCIDRContainmentVectors runs every case in tests/vectors/cidr_containment.json
// through CIDR.Contains and asserts the expected bool. Exercises the primitive
// that all higher-level policy checks reduce to.
func TestCIDRContainmentVectors(t *testing.T) {
	data, err := testvectors.Read("cidr_containment.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			CIDR     string `json:"cidr"`
			IP       string `json:"ip"`
			Expected bool   `json:"expected"`
			Note     string `json:"note,omitempty"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		name := tc.CIDR + "_" + tc.IP
		t.Run(name, func(t *testing.T) {
			cidr, err := ParseCIDR(tc.CIDR, TierIana)
			if err != nil {
				t.Fatalf("parse cidr %q: %v", tc.CIDR, err)
			}
			ip, err := netip.ParseAddr(tc.IP)
			if err != nil {
				t.Fatalf("parse ip %q: %v", tc.IP, err)
			}
			if got := cidr.Contains(ip); got != tc.Expected {
				t.Errorf("Contains(%q, %q) = %v, want %v (%s)", tc.CIDR, tc.IP, got, tc.Expected, tc.Note)
			}
		})
	}
}
