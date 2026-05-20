package ressrfstatic

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

//go:embed testdata/vectors/cidr_containment.json
var cidrContainmentJSON []byte

//go:embed testdata/vectors/ipv4_ipv6_mapping.json
var ipv4IPv6MappingJSON []byte

type cidrContainmentCase struct {
	CIDR     string `json:"cidr"`
	IP       string `json:"ip"`
	Expected bool   `json:"expected"`
	Note     string `json:"note,omitempty"`
}

type ipv4IPv6MappingCase struct {
	Name           string `json:"name"`
	IPv4           string `json:"ipv4"`
	IPv6Mapped     string `json:"ipv6_mapped"`
	CIDR           string `json:"cidr"`
	BothContained  bool   `json:"both_contained"`
	Note           string `json:"note,omitempty"`
}

func TestCIDRContainmentVectors(t *testing.T) {
	var f struct {
		Cases []cidrContainmentCase `json:"cases"`
	}
	if err := json.Unmarshal(cidrContainmentJSON, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for i, c := range f.Cases {
		t.Run(fmt.Sprintf("case_%02d_%s", i, sanitize(c.Note)), func(t *testing.T) {
			cidr, err := ParseCIDR(c.CIDR)
			if err != nil {
				t.Fatalf("parse %q: %v", c.CIDR, err)
			}
			got := cidr.Contains(c.IP)
			if got != c.Expected {
				t.Errorf("Contains(%q in %q) = %v, want %v (%s)", c.IP, c.CIDR, got, c.Expected, c.Note)
			}
		})
	}
}

func TestIPv4IPv6MappingVectors(t *testing.T) {
	var f struct {
		Cases []ipv4IPv6MappingCase `json:"cases"`
	}
	if err := json.Unmarshal(ipv4IPv6MappingJSON, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			cidr, err := ParseCIDR(c.CIDR)
			if err != nil {
				t.Fatalf("parse cidr %q: %v", c.CIDR, err)
			}
			if got := cidr.Contains(c.IPv4); got != c.BothContained {
				t.Errorf("Contains(IPv4=%q in %q) = %v, want %v", c.IPv4, c.CIDR, got, c.BothContained)
			}
			if got := cidr.Contains(c.IPv6Mapped); got != c.BothContained {
				t.Errorf("Contains(IPv6-mapped=%q in %q) = %v, want %v", c.IPv6Mapped, c.CIDR, got, c.BothContained)
			}
		})
	}
}

func TestCIDRStrictRejectsAmbiguous(t *testing.T) {
	// The strict parser must reject octal/hex/zone-id forms.
	bad := []string{
		"0177.0.0.1/32",        // octal
		"0x7f.0.0.1/32",        // hex octet
		"127.0.0.1%eth0/32",    // zone id
		"127.0.0.1",            // missing /
		"127.0.0.0/abc",        // non-numeric prefix
		"192.168.1.1/24",       // host bits set
	}
	for _, s := range bad {
		t.Run(s, func(t *testing.T) {
			if _, err := ParseCIDR(s); err == nil {
				t.Errorf("ParseCIDR(%q) succeeded, want error", s)
			}
		})
	}
}

func TestCIDRSet(t *testing.T) {
	set := NewCIDRSet()
	for _, c := range []string{"10.0.0.0/8", "192.168.0.0/16", "169.254.169.254/32"} {
		cidr, err := ParseCIDR(c)
		if err != nil {
			t.Fatalf("parse %q: %v", c, err)
		}
		set.Add(cidr)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"8.8.8.8", false},
		{"::ffff:10.1.2.3", true},
	}
	for _, c := range cases {
		t.Run(c.ip, func(t *testing.T) {
			match := set.Contains(c.ip)
			got := match != nil
			if got != c.want {
				t.Errorf("Contains(%q) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
}

// sanitize turns a note into a test-name-safe string.
func sanitize(s string) string {
	if s == "" {
		return "noname"
	}
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "_")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}
