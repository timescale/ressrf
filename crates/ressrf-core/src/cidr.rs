use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{DataTier, Error};

/// A parsed CIDR range with precomputed network bytes and mask for fast containment checks.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    /// Normalized to IPv6 (IPv4 mapped to `::ffff:0:0/96` + prefix).
    network: [u8; 16],
    /// Prefix length in the IPv6 address space (0..=128).
    prefix_len: u8,
    /// Precomputed mask bytes for bitwise containment.
    mask: [u8; 16],
    /// Original string representation for display/audit.
    original: String,
    /// Which data tier this CIDR came from.
    source: DataTier,
}

impl fmt::Debug for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cidr")
            .field("original", &self.original)
            .field("prefix_len", &self.prefix_len)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.original)
    }
}

impl Cidr {
    /// Parse a CIDR string (e.g. `192.168.0.0/16` or `fe80::/10`).
    ///
    /// Rejects:
    /// - Octal IP octets (leading zeros like `0177.0.0.1`)
    /// - Hex IP octets (like `0x7f.0.0.1`)
    /// - IPv6 zone IDs (like `fe80::1%eth0/64`)
    /// - Host bits set (the network portion must be correctly masked)
    pub fn parse(s: &str, source: DataTier) -> crate::Result<Self> {
        let s = s.trim();

        // Reject zone IDs
        if s.contains('%') {
            return Err(Error::Parse("zone IDs not allowed in CIDR notation".into()));
        }

        let (addr_str, prefix_str) = s
            .rsplit_once('/')
            .ok_or_else(|| Error::Parse("missing '/' in CIDR notation".into()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| Error::Parse("invalid prefix length".into()))?;

        let ip = parse_ip_strict(addr_str)?;

        let (normalized_ip, adjusted_prefix) = normalize_to_ipv6(ip, prefix_len)?;

        let network_bytes = normalized_ip.octets();
        let mask = compute_mask(adjusted_prefix);

        // Verify network address: all host bits must be zero
        for i in 0..16 {
            if network_bytes[i] & !mask[i] != 0 {
                return Err(Error::Parse("host bits set in network address".into()));
            }
        }

        Ok(Self {
            network: network_bytes,
            prefix_len: adjusted_prefix,
            mask,
            original: String::from(s),
            source,
        })
    }

    /// Parse a CIDR, allowing host bits (auto-masks to network address).
    /// Used for user-supplied ranges where strictness is less important than usability.
    pub fn parse_loose(s: &str, source: DataTier) -> crate::Result<Self> {
        let s = s.trim();

        if s.contains('%') {
            return Err(Error::Parse("zone IDs not allowed in CIDR notation".into()));
        }

        let (addr_str, prefix_str) = s
            .rsplit_once('/')
            .ok_or_else(|| Error::Parse("missing '/' in CIDR notation".into()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| Error::Parse("invalid prefix length".into()))?;

        let ip = parse_ip_strict(addr_str)?;
        let (normalized_ip, adjusted_prefix) = normalize_to_ipv6(ip, prefix_len)?;

        let mut network_bytes = normalized_ip.octets();
        let mask = compute_mask(adjusted_prefix);

        // Zero out host bits
        for i in 0..16 {
            network_bytes[i] &= mask[i];
        }

        Ok(Self {
            network: network_bytes,
            prefix_len: adjusted_prefix,
            mask,
            original: String::from(s),
            source,
        })
    }

    /// Check if an IP address is contained in this CIDR range.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let normalized = match ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        let octets = normalized.octets();

        octets
            .iter()
            .zip(self.mask.iter())
            .zip(self.network.iter())
            .all(|((&octet, &mask), &net)| (octet & mask) == net)
    }

    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    #[must_use]
    pub fn source(&self) -> DataTier {
        self.source
    }

    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }
}

/// A collection of CIDR ranges optimized for containment lookups.
#[derive(Debug, Clone, Default)]
pub struct CidrSet {
    ranges: Vec<Cidr>,
}

impl CidrSet {
    #[must_use]
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn add(&mut self, cidr: Cidr) {
        self.ranges.push(cidr);
    }

    /// Check if any range in the set contains the given IP.
    /// Returns the first matching CIDR if found.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> Option<&Cidr> {
        self.ranges.iter().find(|cidr| cidr.contains(ip))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ranges.len()
    }
}

/// Parse an IP address strictly: reject octal (leading zeros) and hex notation.
fn parse_ip_strict(s: &str) -> crate::Result<IpAddr> {
    let s = s.trim();

    // Try IPv6 first (contains ':')
    if s.contains(':') {
        let v6: Ipv6Addr = s
            .parse()
            .map_err(|e| Error::Parse(alloc::format!("invalid IPv6 address: {e}")))?;
        return Ok(IpAddr::V6(v6));
    }

    // IPv4: check for octal/hex octets
    reject_ambiguous_ipv4(s)?;

    let v4: Ipv4Addr = s
        .parse()
        .map_err(|e| Error::Parse(alloc::format!("invalid IPv4 address: {e}")))?;
    Ok(IpAddr::V4(v4))
}

/// Reject IPv4 addresses with leading zeros (octal) or hex prefixes.
fn reject_ambiguous_ipv4(s: &str) -> crate::Result<()> {
    for octet_str in s.split('.') {
        if octet_str.is_empty() {
            return Err(Error::Parse("empty octet in IPv4 address".into()));
        }
        // Reject hex: "0x..." or "0X..."
        if octet_str.starts_with("0x") || octet_str.starts_with("0X") {
            return Err(Error::Parse(
                "hex notation not allowed in IP addresses".into(),
            ));
        }
        // Reject octal: leading zero followed by more digits (e.g. "0177", "010")
        if octet_str.len() > 1 && octet_str.starts_with('0') {
            return Err(Error::Parse(
                "leading zeros (octal notation) not allowed in IP addresses".into(),
            ));
        }
    }
    Ok(())
}

/// Normalize an IP to IPv6, adjusting the prefix length accordingly.
/// IPv4 addresses get mapped to `::ffff:a.b.c.d` with prefix += 96.
fn normalize_to_ipv6(ip: IpAddr, prefix_len: u8) -> crate::Result<(Ipv6Addr, u8)> {
    match ip {
        IpAddr::V4(v4) => {
            if prefix_len > 32 {
                return Err(Error::Parse("IPv4 prefix length must be 0..=32".into()));
            }
            let mapped = v4.to_ipv6_mapped();
            let adjusted = prefix_len + 96;
            Ok((mapped, adjusted))
        }
        IpAddr::V6(v6) => {
            if prefix_len > 128 {
                return Err(Error::Parse("IPv6 prefix length must be 0..=128".into()));
            }
            Ok((v6, prefix_len))
        }
    }
}

/// Compute a 128-bit mask from a prefix length.
fn compute_mask(prefix_len: u8) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;

    for byte in mask.iter_mut().take(full_bytes) {
        *byte = 0xFF;
    }
    if full_bytes < 16 && remaining_bits > 0 {
        mask[full_bytes] = 0xFF << (8 - remaining_bits);
    }
    mask
}

/// Parse an IP address strictly (for use in policy checks on user-supplied IPs).
/// Exported so the URI validator can reuse it.
pub fn parse_ip(s: &str) -> crate::Result<IpAddr> {
    parse_ip_strict(s)
}

/// Check if a string looks like a bare IP literal (v4 or v6, with optional brackets).
///
/// Uses the strict parser, so ambiguous IPv4 forms (octal `0177.0.0.1`, hex
/// `0x7f000001`, decimal `2130706433`, shorthand `127.1`) return `false` here
/// to avoid silently letting them pass through. Use [`is_ambiguous_ip`] to
/// detect those forms separately.
#[must_use]
pub fn is_ip_literal(s: &str) -> bool {
    let s = s.trim();
    // Bracketed IPv6: [::1]
    let inner = if s.starts_with('[') && s.ends_with(']') {
        &s[1..s.len() - 1]
    } else {
        s
    };
    parse_ip_strict(inner).is_ok()
}

/// Detect host strings that look like an IP address but use ambiguous or
/// non-canonical encodings (decimal integer, octal, hex, shorthand).
///
/// These forms are rejected by [`parse_ip_strict`] and would otherwise be
/// silently treated as DNS hostnames. Examples:
/// - `2130706433` (decimal `127.0.0.1`)
/// - `0177.0.0.1` (octal `127.0.0.1`)
/// - `0x7f000001` or `0x7f.0.0.1` (hex `127.0.0.1`)
/// - `127.1` or `127.0.1` (shorthand `127.0.0.1`)
///
/// Returns `false` for genuine hostnames (`example.com`, `localhost`).
/// Returns `false` for canonical IPv4/IPv6 (use [`is_ip_literal`] for those).
#[must_use]
pub fn is_ambiguous_ip(s: &str) -> bool {
    let s = s.trim();

    // Strip IPv6 brackets if present: bracketed forms are unambiguous IPv6.
    if s.starts_with('[') && s.ends_with(']') {
        return false;
    }

    if s.is_empty() {
        return false;
    }

    // IPv6 (contains ':') is unambiguous: either parses or doesn't.
    if s.contains(':') {
        return false;
    }

    // Already-canonical IPv4 (4 dotted decimal octets) is unambiguous.
    if parse_ip_strict(s).is_ok() {
        return false;
    }

    // Hex IP (`0xNN.0xNN.0xNN.0xNN` or single integer like `0x7f000001`)
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("0x")
        && lower
            .trim_start_matches("0x")
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return true;
    }
    for label in s.split('.') {
        let lower_label = label.to_ascii_lowercase();
        if lower_label.starts_with("0x")
            && lower_label
                .trim_start_matches("0x")
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return true;
        }
    }

    // Decimal integer form: all digits, no dots (e.g. `2130706433`).
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // Dotted form with all-numeric labels.
    if s.contains('.') {
        let mut all_numeric = true;
        let mut octet_count = 0;
        let mut has_octal = false;
        for label in s.split('.') {
            octet_count += 1;
            if label.is_empty() {
                all_numeric = false;
                break;
            }
            if !label.chars().all(|c| c.is_ascii_digit()) {
                all_numeric = false;
                break;
            }
            // Leading-zero octets are octal (e.g. `0177`).
            if label.len() > 1 && label.starts_with('0') {
                has_octal = true;
            }
        }

        if all_numeric {
            // Octal form (e.g. `0177.0.0.1`) -- non-canonical.
            if has_octal {
                return true;
            }
            // Shorthand IPv4 (e.g. `127.1`, `127.0.1`) -- non-canonical.
            if octet_count != 4 {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_cidr() {
        let c = Cidr::parse("192.168.0.0/16", DataTier::Iana).unwrap();
        assert!(c.contains("192.168.1.1".parse().unwrap()));
        assert!(c.contains("192.168.255.255".parse().unwrap()));
        assert!(!c.contains("192.169.0.0".parse().unwrap()));
        assert!(!c.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let c = Cidr::parse("fe80::/10", DataTier::Iana).unwrap();
        assert!(c.contains("fe80::1".parse().unwrap()));
        assert!(c.contains("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!c.contains("ff00::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_containment() {
        // 192.168.0.0/16 should match its IPv4-mapped IPv6 form
        let c = Cidr::parse("192.168.0.0/16", DataTier::Iana).unwrap();
        let mapped: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(c.contains(mapped));
    }

    #[test]
    fn ipv6_cidr_matches_mapped_ipv4() {
        // ::ffff:0.0.0.0/96 should match any IPv4 address (since all IPv4 maps into this)
        let c = Cidr::parse("::ffff:0.0.0.0/96", DataTier::Iana).unwrap();
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(c.contains("192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn reject_octal_ip() {
        let result = Cidr::parse("0177.0.0.1/32", DataTier::Iana);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("octal"));
    }

    #[test]
    fn reject_hex_ip() {
        let result = Cidr::parse("0x7f.0.0.1/32", DataTier::Iana);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hex"));
    }

    #[test]
    fn reject_zone_id() {
        let result = Cidr::parse("fe80::1%eth0/64", DataTier::Iana);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zone"));
    }

    #[test]
    fn slash_zero_matches_everything() {
        let c = Cidr::parse("0.0.0.0/0", DataTier::Iana).unwrap();
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(c.contains("255.255.255.255".parse().unwrap()));
        // /0 in IPv4 means /96 in normalized space, so it matches all IPv4
        assert!(c.contains("192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn slash_128_single_host() {
        let c = Cidr::parse("::1/128", DataTier::Iana).unwrap();
        assert!(c.contains("::1".parse().unwrap()));
        assert!(!c.contains("::2".parse().unwrap()));
    }

    #[test]
    fn slash_32_single_ipv4_host() {
        let c = Cidr::parse("169.254.169.254/32", DataTier::CspMetadata).unwrap();
        assert!(c.contains("169.254.169.254".parse().unwrap()));
        assert!(!c.contains("169.254.169.253".parse().unwrap()));
        assert!(!c.contains("169.254.169.255".parse().unwrap()));
    }

    #[test]
    fn host_bits_set_rejected() {
        let result = Cidr::parse("192.168.1.1/16", DataTier::Iana);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("host bits"));
    }

    #[test]
    fn parse_loose_allows_host_bits() {
        let c = Cidr::parse_loose("192.168.1.1/16", DataTier::UserDeny).unwrap();
        assert!(c.contains("192.168.0.1".parse().unwrap()));
        assert!(c.contains("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn ipv4_prefix_too_large() {
        let result = Cidr::parse("10.0.0.0/33", DataTier::Iana);
        assert!(result.is_err());
    }

    #[test]
    fn ipv6_prefix_too_large() {
        let result = Cidr::parse("::1/129", DataTier::Iana);
        assert!(result.is_err());
    }

    #[test]
    fn cidr_set_contains() {
        let mut set = CidrSet::new();
        set.add(Cidr::parse("10.0.0.0/8", DataTier::Iana).unwrap());
        set.add(Cidr::parse("172.16.0.0/12", DataTier::Iana).unwrap());
        set.add(Cidr::parse("192.168.0.0/16", DataTier::Iana).unwrap());

        assert!(set.contains("10.0.0.1".parse().unwrap()).is_some());
        assert!(set.contains("172.16.0.1".parse().unwrap()).is_some());
        assert!(set.contains("192.168.0.1".parse().unwrap()).is_some());
        assert!(set.contains("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn imds_ranges() {
        let aws_imds = Cidr::parse("169.254.169.254/32", DataTier::CspMetadata).unwrap();
        let aws_ecs = Cidr::parse("169.254.170.2/32", DataTier::CspMetadata).unwrap();
        let azure_wire = Cidr::parse("168.63.129.16/32", DataTier::CspMetadata).unwrap();

        assert!(aws_imds.contains("169.254.169.254".parse().unwrap()));
        assert!(!aws_imds.contains("169.254.169.253".parse().unwrap()));
        assert!(aws_ecs.contains("169.254.170.2".parse().unwrap()));
        assert!(azure_wire.contains("168.63.129.16".parse().unwrap()));
    }

    #[test]
    fn nat64_ranges() {
        let nat64_wk = Cidr::parse("64:ff9b::/96", DataTier::Override).unwrap();
        let nat64_local = Cidr::parse("64:ff9b:1::/48", DataTier::Override).unwrap();

        // NAT64 well-known wraps IPv4 in the low 32 bits
        assert!(nat64_wk.contains("64:ff9b::1.2.3.4".parse().unwrap()));
        assert!(nat64_wk.contains("64:ff9b::c0a8:0001".parse().unwrap()));

        // NAT64 local-use /48
        assert!(nat64_local.contains("64:ff9b:1::1".parse().unwrap()));
        assert!(!nat64_local.contains("64:ff9b:2::1".parse().unwrap()));
    }

    #[test]
    fn six_to_four_range() {
        let six_to_four = Cidr::parse("2002::/16", DataTier::Override).unwrap();
        assert!(six_to_four.contains("2002:c0a8:1::1".parse().unwrap()));
        assert!(!six_to_four.contains("2003::1".parse().unwrap()));
    }

    #[test]
    fn teredo_range() {
        let teredo = Cidr::parse("2001::/32", DataTier::Override).unwrap();
        assert!(teredo.contains("2001::1".parse().unwrap()));
        assert!(teredo.contains("2001:0000:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!teredo.contains("2001:0001::1".parse().unwrap()));
    }

    #[test]
    fn is_ip_literal_detection() {
        assert!(is_ip_literal("1.2.3.4"));
        assert!(is_ip_literal("::1"));
        assert!(is_ip_literal("[::1]"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("not-an-ip"));
    }

    #[test]
    fn is_ip_literal_rejects_ambiguous_forms() {
        // Strict parser rejects octal/hex/shorthand/decimal-integer.
        assert!(!is_ip_literal("0177.0.0.1"));
        assert!(!is_ip_literal("0x7f000001"));
        assert!(!is_ip_literal("0x7f.0.0.1"));
        assert!(!is_ip_literal("2130706433"));
        assert!(!is_ip_literal("127.1"));
    }

    #[test]
    fn is_ambiguous_ip_detection() {
        // Decimal integer form
        assert!(is_ambiguous_ip("2130706433"));
        assert!(is_ambiguous_ip("2852039166"));
        assert!(is_ambiguous_ip("0"));

        // Octal form
        assert!(is_ambiguous_ip("0177.0.0.1"));
        assert!(is_ambiguous_ip("0177.0000.0000.0001"));
        assert!(is_ambiguous_ip("017700000001"));

        // Hex form
        assert!(is_ambiguous_ip("0x7f000001"));
        assert!(is_ambiguous_ip("0xa9fea9fe"));
        assert!(is_ambiguous_ip("0x7f.0x0.0x0.0x1"));
        assert!(is_ambiguous_ip("0X7F000001"));

        // Shorthand form
        assert!(is_ambiguous_ip("127.1"));
        assert!(is_ambiguous_ip("127.0.1"));

        // Mixed (not canonical 4-dot form, hex prefix)
        assert!(is_ambiguous_ip("0x7f.0.0.1"));
    }

    #[test]
    fn is_ambiguous_ip_excludes_canonical() {
        // Canonical IPv4 -- not ambiguous (use is_ip_literal).
        assert!(!is_ambiguous_ip("127.0.0.1"));
        assert!(!is_ambiguous_ip("169.254.169.254"));
        assert!(!is_ambiguous_ip("10.0.0.1"));

        // IPv6 -- not ambiguous.
        assert!(!is_ambiguous_ip("::1"));
        assert!(!is_ambiguous_ip("fe80::1"));
        assert!(!is_ambiguous_ip("[::1]"));
        assert!(!is_ambiguous_ip("[::ffff:127.0.0.1]"));

        // Genuine hostnames -- not ambiguous.
        assert!(!is_ambiguous_ip("example.com"));
        assert!(!is_ambiguous_ip("localhost"));
        assert!(!is_ambiguous_ip("metadata.google.internal"));
        assert!(!is_ambiguous_ip("api.example.com"));

        // Empty / invalid -- not ambiguous.
        assert!(!is_ambiguous_ip(""));
        assert!(!is_ambiguous_ip("not-an-ip"));
    }
}
