package ressrfstatic

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// CIDR is a parsed CIDR range with precomputed network bytes and mask for fast
// containment checks. Both IPv4 and IPv6 CIDRs are normalized to the IPv6
// address space (IPv4 mapped via ::ffff:0:0/96, prefix length +96) so a single
// containment routine handles both families.
//
// Port of crates/ressrf-core/src/cidr.rs Cidr struct.
type CIDR struct {
	network   [16]byte // network address in IPv6 form, host bits cleared
	mask      [16]byte // precomputed bitmask
	prefixLen uint8    // 0..=128 in the IPv6 address space
	original  string   // original input for display/audit
}

// PrefixLen returns the prefix length in IPv6 space (0..=128).
// For an IPv4 CIDR like 10.0.0.0/8 this returns 104 (8 + 96).
func (c *CIDR) PrefixLen() uint8 { return c.prefixLen }

// String returns the original CIDR input verbatim.
func (c *CIDR) String() string { return c.original }

// ParseCIDR strictly parses a CIDR string. Rejects:
//   - IPv6 zone IDs (e.g. "fe80::1%eth0/64")
//   - IPv4 octal octets (e.g. "0177.0.0.1/32")
//   - IPv4 hex octets (e.g. "0x7f.0.0.1/32")
//   - Networks with host bits set (e.g. "192.168.1.1/24")
//   - Missing "/" or non-numeric prefix length
//
// Mirrors crates/ressrf-core/src/cidr.rs::Cidr::parse.
func ParseCIDR(s string) (*CIDR, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "%") {
		return nil, errors.New("ressrfstatic: zone IDs not allowed in CIDR notation")
	}
	slash := strings.LastIndex(s, "/")
	if slash < 0 {
		return nil, errors.New("ressrfstatic: missing '/' in CIDR notation")
	}
	addrStr, prefixStr := s[:slash], s[slash+1:]

	prefixI, err := strconv.Atoi(prefixStr)
	if err != nil || prefixI < 0 {
		return nil, errors.New("ressrfstatic: invalid prefix length")
	}
	prefix := uint8(prefixI)

	addr, isV4, err := parseIPStrict(addrStr)
	if err != nil {
		return nil, err
	}

	// Normalize to IPv6 + adjust prefix length.
	octets, prefix, err := normalizeToIPv6(addr, isV4, prefix)
	if err != nil {
		return nil, err
	}
	mask := computeMask(prefix)

	// Strict: reject host bits set.
	for i := 0; i < 16; i++ {
		if octets[i]&^mask[i] != 0 {
			return nil, fmt.Errorf("ressrfstatic: host bits set in network address %q", s)
		}
	}

	return &CIDR{
		network:   octets,
		mask:      mask,
		prefixLen: prefix,
		original:  s,
	}, nil
}

// ParseCIDRLoose is like ParseCIDR but auto-masks host bits instead of
// rejecting them. Used for user-supplied ranges where strictness loses to
// usability. Mirrors Cidr::parse_loose.
func ParseCIDRLoose(s string) (*CIDR, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "%") {
		return nil, errors.New("ressrfstatic: zone IDs not allowed in CIDR notation")
	}
	slash := strings.LastIndex(s, "/")
	if slash < 0 {
		return nil, errors.New("ressrfstatic: missing '/' in CIDR notation")
	}
	addrStr, prefixStr := s[:slash], s[slash+1:]

	prefixI, err := strconv.Atoi(prefixStr)
	if err != nil || prefixI < 0 {
		return nil, errors.New("ressrfstatic: invalid prefix length")
	}
	prefix := uint8(prefixI)

	addr, isV4, err := parseIPStrict(addrStr)
	if err != nil {
		return nil, err
	}
	octets, prefix, err := normalizeToIPv6(addr, isV4, prefix)
	if err != nil {
		return nil, err
	}
	mask := computeMask(prefix)
	for i := 0; i < 16; i++ {
		octets[i] &= mask[i]
	}
	return &CIDR{network: octets, mask: mask, prefixLen: prefix, original: s}, nil
}

// normalizeToIPv6 returns the address as 16 octets in IPv4-mapped form for v4
// inputs (::ffff:a.b.c.d), and adjusts the prefix length by +96. Mirrors
// crates/ressrf-core/src/cidr.rs::normalize_to_ipv6.
func normalizeToIPv6(addr netip.Addr, isV4 bool, prefix uint8) ([16]byte, uint8, error) {
	if isV4 {
		if prefix > 32 {
			return [16]byte{}, 0, errors.New("ressrfstatic: IPv4 prefix length must be 0..=32")
		}
		v4 := addr.As4()
		var out [16]byte
		out[10] = 0xFF
		out[11] = 0xFF
		out[12], out[13], out[14], out[15] = v4[0], v4[1], v4[2], v4[3]
		return out, prefix + 96, nil
	}
	if prefix > 128 {
		return [16]byte{}, 0, errors.New("ressrfstatic: IPv6 prefix length must be 0..=128")
	}
	return addr.As16(), prefix, nil
}

// Contains reports whether the given IP literal is within this range.
// Both IPv4 and IPv6 input are accepted; IPv4 is normalized to ::ffff:a.b.c.d
// the same way the network address was, so an IPv4 CIDR matches both
// "1.2.3.4" and "::ffff:1.2.3.4".
//
// Returns false for inputs that don't strictly parse (octal/hex/zone-id).
func (c *CIDR) Contains(ipStr string) bool {
	octets, ok := normalizeIPv4MappedOctets(ipStr)
	if !ok {
		return false
	}
	for i := 0; i < 16; i++ {
		if octets[i]&c.mask[i] != c.network[i] {
			return false
		}
	}
	return true
}

// normalizeIPv4MappedOctets parses an IP literal and returns it in 16-byte
// IPv4-mapped IPv6 form (::ffff:a.b.c.d for v4 inputs). Returns (_, false)
// for inputs that don't strictly parse (octal, hex, zone-id, garbage).
func normalizeIPv4MappedOctets(ipStr string) ([16]byte, bool) {
	addr, isV4, err := parseIPStrict(ipStr)
	if err != nil {
		return [16]byte{}, false
	}
	if isV4 {
		v4 := addr.As4()
		var out [16]byte
		out[10] = 0xFF
		out[11] = 0xFF
		out[12], out[13], out[14], out[15] = v4[0], v4[1], v4[2], v4[3]
		return out, true
	}
	return addr.As16(), true
}

// CIDRSet is an append-only collection of CIDR ranges with linear-scan
// containment lookups. Matches the Rust CidrSet shape (Vec<Cidr> + first-match
// semantics); list sizes are small enough (low hundreds at worst) that a trie
// is unnecessary.
type CIDRSet struct {
	ranges []*CIDR
}

func NewCIDRSet() *CIDRSet { return &CIDRSet{} }

func (s *CIDRSet) Add(c *CIDR) { s.ranges = append(s.ranges, c) }

// Contains returns the first matching range or nil.
func (s *CIDRSet) Contains(ipStr string) *CIDR {
	octets, ok := normalizeIPv4MappedOctets(ipStr)
	if !ok {
		return nil
	}
	for _, c := range s.ranges {
		matched := true
		for i := 0; i < 16; i++ {
			if octets[i]&c.mask[i] != c.network[i] {
				matched = false
				break
			}
		}
		if matched {
			return c
		}
	}
	return nil
}

func (s *CIDRSet) Len() int     { return len(s.ranges) }
func (s *CIDRSet) Empty() bool  { return len(s.ranges) == 0 }
func (s *CIDRSet) Ranges() []*CIDR {
	out := make([]*CIDR, len(s.ranges))
	copy(out, s.ranges)
	return out
}

// parseIPStrict parses an IPv4 or IPv6 literal, rejecting ambiguous IPv4 forms
// (octal/hex octets). Returns the address and whether the input was an IPv4
// dotted-decimal literal.
//
// Mirrors crates/ressrf-core/src/cidr.rs::parse_ip_strict + reject_ambiguous_ipv4.
func parseIPStrict(s string) (netip.Addr, bool, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ":") {
		// IPv6. netip.ParseAddr rejects zone IDs that we don't pre-strip,
		// but we already reject zone IDs at the CIDR layer. Also handle
		// IPv4-mapped IPv6 like ::ffff:127.0.0.1.
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, false, fmt.Errorf("ressrfstatic: invalid IPv6 address %q: %w", s, err)
		}
		return addr, false, nil
	}
	// IPv4: reject octal/hex octets before letting netip parse.
	if err := rejectAmbiguousIPv4(s); err != nil {
		return netip.Addr{}, false, err
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("ressrfstatic: invalid IPv4 address %q: %w", s, err)
	}
	if !addr.Is4() {
		return netip.Addr{}, false, fmt.Errorf("ressrfstatic: expected IPv4, got %q", s)
	}
	return addr, true, nil
}

func rejectAmbiguousIPv4(s string) error {
	for _, octet := range strings.Split(s, ".") {
		if octet == "" {
			return errors.New("ressrfstatic: empty octet in IPv4 address")
		}
		low := strings.ToLower(octet)
		if strings.HasPrefix(low, "0x") {
			return errors.New("ressrfstatic: hex notation not allowed in IP addresses")
		}
		if len(octet) > 1 && octet[0] == '0' {
			return errors.New("ressrfstatic: leading zeros (octal notation) not allowed in IP addresses")
		}
	}
	return nil
}

func computeMask(prefixLen uint8) [16]byte {
	var mask [16]byte
	full := int(prefixLen / 8)
	rem := prefixLen % 8
	for i := 0; i < full && i < 16; i++ {
		mask[i] = 0xFF
	}
	if full < 16 && rem > 0 {
		mask[full] = 0xFF << (8 - rem)
	}
	return mask
}

// IsIPLiteral reports whether s parses as a strict IP literal (v4 or v6,
// optional IPv6 brackets). Ambiguous IPv4 forms return false.
// Mirrors cidr.rs::is_ip_literal.
func IsIPLiteral(s string) bool {
	s = strings.TrimSpace(s)
	inner := s
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner = s[1 : len(s)-1]
	}
	_, _, err := parseIPStrict(inner)
	return err == nil
}

// IsAmbiguousIP reports whether s looks like an IP literal but uses an
// ambiguous/non-canonical encoding (decimal integer, octal, hex, shorthand).
// Used by the URI validator to reject hosts that would otherwise be silently
// treated as DNS names. Mirrors cidr.rs::is_ambiguous_ip.
func IsAmbiguousIP(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return false
	}
	if s == "" || strings.Contains(s, ":") {
		return false
	}
	// Canonical IPv4 — unambiguous.
	if _, _, err := parseIPStrict(s); err == nil {
		return false
	}
	low := strings.ToLower(s)
	// Single hex integer like "0x7f000001".
	if strings.HasPrefix(low, "0x") && allASCIIHex(low[2:]) {
		return true
	}
	// Per-label hex (e.g. "0x7f.0.0.1").
	for _, label := range strings.Split(s, ".") {
		ll := strings.ToLower(label)
		if strings.HasPrefix(ll, "0x") && allASCIIHex(ll[2:]) {
			return true
		}
	}
	// Pure decimal integer (e.g. "2130706433").
	if allASCIIDigit(s) {
		return true
	}
	// Dotted form with all-numeric labels (octal or shorthand).
	if strings.Contains(s, ".") {
		var allNumeric = true
		var hasOctal = false
		var octetCount = 0
		for _, label := range strings.Split(s, ".") {
			octetCount++
			if label == "" || !allASCIIDigit(label) {
				allNumeric = false
				break
			}
			if len(label) > 1 && label[0] == '0' {
				hasOctal = true
			}
		}
		if allNumeric {
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

func allASCIIHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func allASCIIDigit(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
