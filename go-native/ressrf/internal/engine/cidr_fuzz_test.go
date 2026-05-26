package engine

import (
	"net/netip"
	"testing"
)

// FuzzParseCIDR mirrors fuzz/fuzz_targets/fuzz_cidr.rs (strict parser).
// Invariant: parsing never panics; a successfully parsed CIDR can be queried
// for any IP without panicking; ParseCIDR is deterministic.
func FuzzParseCIDR(f *testing.F) {
	seeds := []string{
		// Canonical, parses cleanly.
		"10.0.0.0/8",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.169.254/32",
		"0.0.0.0/0",
		"::1/128",
		"fe80::/10",
		"2001:db8::/32",
		"64:ff9b::/96",
		"::ffff:0:0/96",
		// Strict-parser rejects (must not panic, must return error).
		"0177.0.0.1/32",
		"0x7f.0.0.1/32",
		"fe80::1%eth0/64",
		"192.168.1.1/16",
		"10.0.0.0/33",
		"::1/129",
		"",
		"/",
		"abc/24",
		"10.0.0.0/abc",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c1, err1 := ParseCIDR(s, TierIana)
		c2, err2 := ParseCIDR(s, TierIana)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic parse: %v vs %v", err1, err2)
		}
		if err1 != nil {
			return
		}
		if c1.Original != c2.Original {
			t.Fatalf("non-deterministic Original: %q vs %q", c1.Original, c2.Original)
		}
		// Containment never panics for any address.
		for _, addr := range fuzzProbeAddrs {
			_ = c1.Contains(addr)
		}
	})
}

// FuzzParseCIDRLoose is the same shape as FuzzParseCIDR but for the loose
// parser that masks host bits silently.
func FuzzParseCIDRLoose(f *testing.F) {
	seeds := []string{
		"10.0.0.0/8",
		"192.168.1.42/16", // host bits set — loose accepts
		"10.42.0.0/16",
		"::1/128",
		"fe80::1/10", // host bits set in v6
		"203.0.113.0/24",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCIDRLoose(s, TierUserDeny)
		if err != nil {
			return
		}
		// Loose-parsed CIDR's stored prefix must equal its masked form
		// (the parser zeroed any host bits).
		if c.Prefix.Masked() != c.Prefix {
			t.Fatalf("loose-parsed prefix not masked: %v", c.Prefix)
		}
		for _, addr := range fuzzProbeAddrs {
			_ = c.Contains(addr)
		}
	})
}

// FuzzIsAmbiguousIP guards the parser against any input that would silently
// flip categorization between IsIPLiteral and IsAmbiguousIP, which would
// punch a hole in the URI validator's BS-1 defence.
func FuzzIsAmbiguousIP(f *testing.F) {
	seeds := []string{
		// Ambiguous forms — must return true.
		"2130706433", "0", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1",
		"017700000001", "0xa9fea9fe", "127.1", "127.0.1", "0X7F000001",
		// Canonical — must return false.
		"127.0.0.1", "::1", "[::1]", "fe80::1", "example.com", "localhost", "",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		amb := IsAmbiguousIP(s)
		lit := IsIPLiteral(s)
		// A string cannot be BOTH an unambiguous IP literal AND an
		// ambiguous encoding — IsIPLiteral excludes ambiguous forms by
		// construction, and IsAmbiguousIP rejects canonical IPv4 / IPv6.
		// This invariant is what makes the URI validator's BS-1 chain
		// safe; if it ever breaks, we've opened a parser-confusion gap.
		if amb && lit {
			t.Fatalf("%q is both an IP literal and ambiguous", s)
		}
	})
}

// fuzzProbeAddrs is a small set of IPs used to exercise Contains during
// fuzzing. Allocated once at init to keep the per-iteration cost low.
var fuzzProbeAddrs = func() []netip.Addr {
	addrs := []string{
		"0.0.0.0", "10.0.0.1", "127.0.0.1", "169.254.169.254",
		"192.168.1.1", "8.8.8.8", "255.255.255.255",
		"::", "::1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1",
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}()
