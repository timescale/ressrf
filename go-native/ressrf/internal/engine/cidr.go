package engine

import (
	"net/netip"
	"strconv"
	"strings"
)

// CIDR is a parsed CIDR range tagged with the tier it came from.
//
// The underlying matcher uses netip.Prefix in its canonical (Masked) form so
// containment checks are allocation-free and handle IPv4-mapped IPv6 the same
// way as the Rust core (which normalizes everything to ::ffff:0:0/96-relative).
type CIDR struct {
	Prefix   netip.Prefix
	Original string
	Source   DataTier
}

func (c CIDR) String() string { return c.Original }

// ParseCIDR is the strict parser used for built-in / IANA / cloud-module
// entries. It rejects: octal IPv4 octets, hex IPv4 octets, IPv6 zone IDs, and
// host bits set in the network portion.
func ParseCIDR(s string, source DataTier) (CIDR, error) {
	return parseCIDR(s, source, true)
}

// ParseCIDRLoose is the user-facing parser: same as ParseCIDR but it accepts
// host bits and silently masks them to the network address.
func ParseCIDRLoose(s string, source DataTier) (CIDR, error) {
	return parseCIDR(s, source, false)
}

func parseCIDR(s string, source DataTier, strict bool) (CIDR, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "%") {
		return CIDR{}, &ParseError{Detail: "zone IDs not allowed in CIDR notation"}
	}
	slash := strings.LastIndexByte(s, '/')
	if slash < 0 {
		return CIDR{}, &ParseError{Detail: "missing '/' in CIDR notation"}
	}
	addrStr, prefixStr := s[:slash], s[slash+1:]

	prefixLen64, err := strconv.ParseUint(prefixStr, 10, 32)
	if err != nil {
		return CIDR{}, &ParseError{Detail: "invalid prefix length"}
	}
	prefixLen := int(prefixLen64)

	addr, perr := parseIPStrict(addrStr)
	if perr != nil {
		return CIDR{}, perr
	}

	maxPrefix := 128
	if addr.Is4() {
		maxPrefix = 32
	}
	if prefixLen > maxPrefix {
		return CIDR{}, &ParseError{Detail: "prefix length exceeds address family maximum"}
	}

	prefix, perr2 := netip.AddrFrom16(addr.As16()).Prefix(addrPrefixBits(addr, prefixLen))
	if perr2 != nil {
		return CIDR{}, &ParseError{Detail: "invalid prefix: " + perr2.Error()}
	}
	if strict {
		if prefix.Masked() != prefix {
			return CIDR{}, &ParseError{Detail: "host bits set in network address"}
		}
		return CIDR{Prefix: prefix, Original: s, Source: source}, nil
	}
	return CIDR{Prefix: prefix.Masked(), Original: s, Source: source}, nil
}

// Contains reports whether the given address falls inside this CIDR.
func (c CIDR) Contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	return c.Prefix.Contains(netip.AddrFrom16(addr.As16()))
}

// NativePrefix returns the prefix in native form: an IPv4 range is returned as
// a 4-byte (Is4) prefix rather than the IPv4-mapped IPv6 form the matcher
// stores internally (a.b.c.d/n instead of ::ffff:a.b.c.d/(n+96)). IPv6 ranges
// are returned unchanged. Use this when handing the range to code that expects
// human / family-native CIDRs, e.g. rendering a Kubernetes NetworkPolicy
// except-list.
func (c CIDR) NativePrefix() netip.Prefix {
	addr := c.Prefix.Addr()
	if addr.Is4In6() {
		return netip.PrefixFrom(addr.Unmap(), c.Prefix.Bits()-96)
	}
	return c.Prefix
}

// CIDRSet is a flat collection of CIDRs scanned in insertion order. The Rust
// core uses the same linear scan; for ~30 entries it outperforms tree
// structures because of cache locality.
type CIDRSet struct {
	Ranges []CIDR
}

func (s *CIDRSet) Add(c CIDR) { s.Ranges = append(s.Ranges, c) }

// Contains returns the first CIDR in the set that matches the address, or nil.
func (s *CIDRSet) Contains(addr netip.Addr) *CIDR {
	for i := range s.Ranges {
		if s.Ranges[i].Contains(addr) {
			return &s.Ranges[i]
		}
	}
	return nil
}

func (s *CIDRSet) Len() int      { return len(s.Ranges) }
func (s *CIDRSet) IsEmpty() bool { return len(s.Ranges) == 0 }

// addrPrefixBits returns the prefix length in the IPv6 address space: IPv4
// addresses are normalized to ::ffff:a.b.c.d so their prefix shifts by 96.
func addrPrefixBits(addr netip.Addr, prefixLen int) int {
	if addr.Is4() {
		return prefixLen + 96
	}
	return prefixLen
}

// parseIPStrict parses an IP literal while rejecting Rust-style ambiguous
// IPv4 forms (octal, hex, shorthand). It does not strip brackets.
func parseIPStrict(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ":") {
		// Rust's stdlib Ipv6Addr::from_str rejects RFC 6874 zone identifiers
		// (the `%scope` suffix). Go's netip.ParseAddr accepts them. Match
		// Rust's stricter behavior so the differential harness sees identical
		// IP-literal decisions on both sides; URLs that look like IPv6+zone
		// fall through to hostname treatment in both engines.
		if strings.Contains(s, "%") {
			return netip.Addr{}, &ParseError{Detail: "zone IDs not allowed in IP address"}
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, &ParseError{Detail: "invalid IPv6 address: " + err.Error()}
		}
		return addr, nil
	}
	if err := rejectAmbiguousIPv4(s); err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, &ParseError{Detail: "invalid IPv4 address: " + err.Error()}
	}
	if !addr.Is4() {
		return netip.Addr{}, &ParseError{Detail: "expected IPv4 address"}
	}
	return addr, nil
}

func rejectAmbiguousIPv4(s string) error {
	for octet := range strings.SplitSeq(s, ".") {
		if octet == "" {
			return &ParseError{Detail: "empty octet in IPv4 address"}
		}
		if strings.HasPrefix(octet, "0x") || strings.HasPrefix(octet, "0X") {
			return &ParseError{Detail: "hex notation not allowed in IP addresses"}
		}
		if len(octet) > 1 && octet[0] == '0' {
			return &ParseError{Detail: "leading zeros (octal notation) not allowed in IP addresses"}
		}
	}
	return nil
}

// ParseIP exposes the strict parser for use by the URI validator.
func ParseIP(s string) (netip.Addr, error) { return parseIPStrict(s) }

// IsIPLiteral reports whether s looks like an unambiguous IP literal, with
// optional brackets. Ambiguous forms (octal, hex, decimal, shorthand) return
// false here; call IsAmbiguousIP separately to detect those.
func IsIPLiteral(s string) bool {
	s = strings.TrimSpace(s)
	inner := s
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner = s[1 : len(s)-1]
	}
	_, err := parseIPStrict(inner)
	return err == nil
}

// IsAmbiguousIP detects hosts that look like IPs but use non-canonical
// encodings (decimal integer, octal, hex, shorthand). These must be rejected
// before reaching DNS to prevent silent fall-through to internal resolvers.
func IsAmbiguousIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Bracketed = IPv6, unambiguous (parses or doesn't).
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return false
	}
	// IPv6 with colons: unambiguous.
	if strings.Contains(s, ":") {
		return false
	}
	// Canonical 4-octet IPv4: unambiguous.
	if _, err := parseIPStrict(s); err == nil {
		return false
	}
	lower := strings.ToLower(s)
	if isAmbiguousHexLabel(lower) {
		return true
	}
	for label := range strings.SplitSeq(lower, ".") {
		if isAmbiguousHexLabel(label) {
			return true
		}
	}
	if allDigits(s) {
		return true
	}
	if strings.Contains(s, ".") {
		allNum := true
		hasOctal := false
		octetCount := 0
		for label := range strings.SplitSeq(s, ".") {
			octetCount++
			if label == "" {
				allNum = false
				break
			}
			if !allDigits(label) {
				allNum = false
				break
			}
			if len(label) > 1 && label[0] == '0' {
				hasOctal = true
			}
		}
		if allNum {
			if hasOctal {
				return true
			}
			if octetCount != 4 {
				return true
			}
		}
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isAmbiguousHexLabel mirrors Rust's `lower.starts_with("0x") &&
// trim_start_matches("0x").chars().all(is_ascii_hexdigit)`. The Rust
// trim strips ALL leading "0x" pairs (so "0x0x0" -> "0"), and `.all()`
// on an empty tail is vacuously true (so bare "0x" is itself ambiguous).
// Caller must pass an already-lowercased string.
func isAmbiguousHexLabel(s string) bool {
	if !strings.HasPrefix(s, "0x") {
		return false
	}
	tail := s
	for strings.HasPrefix(tail, "0x") {
		tail = tail[2:]
	}
	return tail == "" || allHexDigits(tail)
}

func allHexDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
