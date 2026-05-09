//! Default deny list sourced from IANA special-purpose registries plus hand-curated overrides.
//!
//! Tier 1a: IANA ranges where Globally Reachable = False (non-routable/reserved).
//! Tier 1b: IANA infrastructure ranges (Globally Reachable = True but no legitimate SSRF
//!     destination use case: AS112, AMT, deprecated 6to4 relay).
//! Tier 1c: Overrides for ranges that wrap attacker-controlled IPv4 inside IPv6 (6to4,
//!     Teredo, NAT64). Critical for IPv6-only k8s with DNS64.
//! Tier 2: CSP metadata endpoints (IMDS, Wireserver, ECS).

use alloc::vec::Vec;

use crate::cidr::Cidr;
use crate::error::DataTier;

/// IANA IPv4 special-purpose ranges where Globally Reachable = False, plus
/// infrastructure-only ranges (Tier 1b) that have no legitimate SSRF target use.
pub const IANA_IPV4_DENY: &[&str] = &[
    "0.0.0.0/8",          // "This network" (RFC 791)
    "10.0.0.0/8",         // Private-Use (RFC 1918)
    "100.64.0.0/10",      // Shared Address Space / CGNAT (RFC 6598)
    "127.0.0.0/8",        // Loopback (RFC 1122)
    "169.254.0.0/16",     // Link-Local (RFC 3927)
    "172.16.0.0/12",      // Private-Use (RFC 1918)
    "192.0.0.0/24",       // IETF Protocol Assignments (RFC 6890)
    "192.0.2.0/24",       // Documentation TEST-NET-1 (RFC 5737)
    "192.31.196.0/24",    // AS112-v4 (RFC 7535) [Tier 1b: globally reachable but infra-only]
    "192.52.193.0/24",    // AMT (RFC 7450) [Tier 1b: globally reachable but infra-only]
    "192.88.99.0/24",     // Deprecated 6to4 relay anycast (RFC 7526)
    "192.168.0.0/16",     // Private-Use (RFC 1918)
    "192.175.48.0/24",    // Direct Delegation AS112 (RFC 7534) [Tier 1b]
    "198.18.0.0/15",      // Benchmarking (RFC 2544)
    "198.51.100.0/24",    // Documentation TEST-NET-2 (RFC 5737)
    "203.0.113.0/24",     // Documentation TEST-NET-3 (RFC 5737)
    "224.0.0.0/4",        // Multicast (RFC 5771)
    "240.0.0.0/4",        // Reserved (RFC 1112, Section 4)
    "255.255.255.255/32", // Limited Broadcast (RFC 919)
];

/// IANA IPv6 special-purpose ranges where Globally Reachable = False.
///
/// Note: `::ffff:0:0/96` (IPv4-mapped) is intentionally excluded because it
/// encompasses ALL IPv4 addresses after normalization. IPv4 addresses are
/// already validated against the IPv4 deny list.
pub const IANA_IPV6_DENY: &[&str] = &[
    "::1/128",        // Loopback (RFC 4291)
    "::/128",         // Unspecified (RFC 4291)
    "64:ff9b:1::/48", // IPv4-IPv6 Translation local-use (RFC 8215)
    "100::/64",       // Discard-Only (RFC 6666)
    "100:0:0:1::/64", // Dummy IPv6 Prefix (RFC 9780, 2025-04)
    "2001:db8::/32",  // Documentation (RFC 3849)
    "2001:2::/48",    // Benchmarking (RFC 5180)
    "3fff::/20",      // Documentation (RFC 9637, 2024-07)
    "5f00::/16",      // Segment Routing SRv6 SIDs (RFC 9602, 2024-04)
    "fc00::/7",       // Unique-Local (RFC 4193)
    "fe80::/10",      // Link-Local Unicast (RFC 4291)
    "ff00::/8",       // Multicast (RFC 4291)
];

/// Tier 1c: Override ranges where IANA marks Globally Reachable = True/N/A but that
/// wrap attacker-controlled IPv4 inside IPv6. Critical for IPv6-only k8s with DNS64.
pub const OVERRIDE_DENY: &[&str] = &[
    "2002::/16",    // 6to4 (wraps arbitrary IPv4 in bits 16..47, RFC 3056)
    "2001::/32",    // Teredo (wraps arbitrary IPv4, RFC 4380)
    "64:ff9b::/96", // NAT64 well-known prefix (wraps IPv4 in low 32 bits, RFC 6052)
];

/// Tier 2: Cloud provider metadata endpoints. These are essentially permanent.
pub const CSP_METADATA_DENY: &[&str] = &[
    "169.254.169.254/32", // AWS/Azure/GCP IMDS
    "169.254.170.2/32",   // AWS ECS task metadata
    "168.63.129.16/32",   // Azure Wireserver / DHCP
    "fd00:ec2::254/128",  // AWS IMDSv2 IPv6
];

/// Build the complete default deny set as parsed CIDRs.
pub fn default_deny_set() -> Vec<Cidr> {
    let mut result = Vec::with_capacity(
        IANA_IPV4_DENY.len() + IANA_IPV6_DENY.len() + OVERRIDE_DENY.len() + CSP_METADATA_DENY.len(),
    );

    for &cidr_str in IANA_IPV4_DENY {
        if let Ok(cidr) = Cidr::parse(cidr_str, DataTier::Iana) {
            result.push(cidr);
        }
    }

    for &cidr_str in IANA_IPV6_DENY {
        if let Ok(cidr) = Cidr::parse(cidr_str, DataTier::Iana) {
            result.push(cidr);
        }
    }

    for &cidr_str in OVERRIDE_DENY {
        if let Ok(cidr) = Cidr::parse(cidr_str, DataTier::Override) {
            result.push(cidr);
        }
    }

    for &cidr_str in CSP_METADATA_DENY {
        if let Ok(cidr) = Cidr::parse(cidr_str, DataTier::CspMetadata) {
            result.push(cidr);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::IpAddr;

    #[test]
    fn all_ranges_parse_successfully() {
        for &s in IANA_IPV4_DENY {
            Cidr::parse(s, DataTier::Iana).unwrap_or_else(|e| panic!("Failed to parse {s}: {e}"));
        }
        for &s in IANA_IPV6_DENY {
            Cidr::parse(s, DataTier::Iana).unwrap_or_else(|e| panic!("Failed to parse {s}: {e}"));
        }
        for &s in OVERRIDE_DENY {
            Cidr::parse(s, DataTier::Override)
                .unwrap_or_else(|e| panic!("Failed to parse {s}: {e}"));
        }
        for &s in CSP_METADATA_DENY {
            Cidr::parse(s, DataTier::CspMetadata)
                .unwrap_or_else(|e| panic!("Failed to parse {s}: {e}"));
        }
    }

    #[test]
    fn default_deny_set_blocks_private_ranges() {
        let deny = default_deny_set();
        let private_ips: &[&str] = &[
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "169.254.170.2",
            "168.63.129.16",
        ];
        for &ip_str in private_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let matched = deny.iter().any(|c| c.contains(ip));
            assert!(matched, "Expected {ip_str} to be in deny set");
        }
    }

    #[test]
    fn default_deny_set_allows_public() {
        let deny = default_deny_set();
        let public_ips: &[&str] = &["8.8.8.8", "1.1.1.1", "151.101.1.67"];
        for &ip_str in public_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let matched = deny.iter().any(|c| c.contains(ip));
            assert!(!matched, "Expected {ip_str} to NOT be in deny set");
        }
    }

    #[test]
    fn deny_set_covers_cgnat() {
        let deny = default_deny_set();
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(ip)));
    }

    #[test]
    fn deny_set_covers_ipv6_transitions() {
        let deny = default_deny_set();
        // 6to4
        let six_to_four: IpAddr = "2002:c0a8:1::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(six_to_four)));
        // Teredo
        let teredo: IpAddr = "2001:0000:1234::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(teredo)));
        // NAT64 well-known
        let nat64: IpAddr = "64:ff9b::192.168.1.1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(nat64)));
    }

    #[test]
    fn deny_set_covers_multicast() {
        let deny = default_deny_set();
        let ipv4_mcast: IpAddr = "224.0.0.1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(ipv4_mcast)));
        let ipv4_mcast_high: IpAddr = "239.255.255.255".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(ipv4_mcast_high)));
        let ipv6_mcast: IpAddr = "ff02::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(ipv6_mcast)));
    }

    #[test]
    fn deny_set_covers_recent_ipv6_allocations() {
        let deny = default_deny_set();
        // Dummy IPv6 Prefix (RFC 9780)
        let dummy: IpAddr = "100:0:0:1::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(dummy)));
        // Documentation (RFC 9637)
        let doc: IpAddr = "3fff::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(doc)));
        // SRv6 SIDs (RFC 9602)
        let srv6: IpAddr = "5f00::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(srv6)));
    }
}
