//! Default deny list sourced from IANA special-purpose registries plus hand-curated overrides.
//!
//! Constants are generated at build time from `config/ip_ranges.json` via `build.rs`.
//! To modify the deny list, edit the JSON source and rebuild.
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

include!(concat!(env!("OUT_DIR"), "/ip_ranges_generated.rs"));

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
        let six_to_four: IpAddr = "2002:c0a8:1::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(six_to_four)));
        let teredo: IpAddr = "2001:0000:1234::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(teredo)));
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
        let dummy: IpAddr = "100:0:0:1::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(dummy)));
        let doc: IpAddr = "3fff::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(doc)));
        let srv6: IpAddr = "5f00::1".parse().unwrap();
        assert!(deny.iter().any(|c| c.contains(srv6)));
    }
}
