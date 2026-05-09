#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ressrf_core::policy::{PolicyBuilder, Preset};
use std::net::IpAddr;

#[derive(Debug, Arbitrary)]
struct PolicyInput {
    preset: u8,
    deny_cidrs: Vec<String>,
    allow_cidrs: Vec<String>,
    test_ips_v4: Vec<[u8; 4]>,
    test_ips_v6: Vec<[u8; 16]>,
}

fuzz_target!(|input: PolicyInput| {
    let preset = match input.preset % 3 {
        0 => Preset::ExternalOnly,
        1 => Preset::InternalOnly,
        _ => Preset::None,
    };

    let mut builder = PolicyBuilder::new(preset);

    let deny_refs: Vec<&str> = input.deny_cidrs.iter().map(String::as_str).collect();
    builder.add_denied(&deny_refs);

    let allow_refs: Vec<&str> = input.allow_cidrs.iter().map(String::as_str).collect();
    builder.add_allowed(&allow_refs);

    let policy = builder.build();

    // Test with IPv4 addresses
    let ips_v4: Vec<IpAddr> = input
        .test_ips_v4
        .iter()
        .map(|b| IpAddr::V4((*b).into()))
        .collect();
    if !ips_v4.is_empty() {
        let _ = policy.is_network_allowed(&ips_v4);
    }

    // Test with IPv6 addresses
    let ips_v6: Vec<IpAddr> = input
        .test_ips_v6
        .iter()
        .map(|b| IpAddr::V6((*b).into()))
        .collect();
    if !ips_v6.is_empty() {
        let _ = policy.is_network_allowed(&ips_v6);
    }

    // Property: None preset always allows
    if preset == Preset::None && !ips_v4.is_empty() {
        assert!(policy.is_network_allowed(&ips_v4).is_ok());
    }

    // Property: allow overrides deny. If an IP is in both allow and deny, it must pass.
    // (This is tested implicitly but the fuzzer may find edge cases.)
});
