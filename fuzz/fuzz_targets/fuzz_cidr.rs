#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ressrf_core::cidr::Cidr;
use ressrf_core::error::DataTier;
use std::net::IpAddr;

#[derive(Debug, Arbitrary)]
struct CidrInput {
    cidr_string: String,
    ip_bytes_v4: [u8; 4],
    ip_bytes_v6: [u8; 16],
    use_v6: bool,
}

fuzz_target!(|input: CidrInput| {
    // Fuzz CIDR parsing: should never panic, only return Ok/Err
    let _ = Cidr::parse(&input.cidr_string, DataTier::Iana);
    let _ = Cidr::parse_loose(&input.cidr_string, DataTier::UserDeny);

    // If parsing succeeds, containment check should never panic
    if let Ok(cidr) = Cidr::parse_loose(&input.cidr_string, DataTier::Iana) {
        let ip: IpAddr = if input.use_v6 {
            IpAddr::V6(input.ip_bytes_v6.into())
        } else {
            IpAddr::V4(input.ip_bytes_v4.into())
        };
        let _ = cidr.contains(ip);

        // Property: a CIDR with prefix /0 must contain any IP of its family
        if cidr.prefix_len() == 96 {
            // /0 IPv4 normalizes to /96, should contain any IPv4
            let test_ip = IpAddr::V4(input.ip_bytes_v4.into());
            assert!(
                cidr.contains(test_ip) || !input.cidr_string.starts_with("0.0.0.0"),
                "CIDR 0.0.0.0/0 must contain all IPv4"
            );
        }
    }
});
