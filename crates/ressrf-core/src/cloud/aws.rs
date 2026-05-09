//! AWS cloud module: IMDS/ECS deny ranges and internal domain suffixes.

/// Tier 2 deny ranges for AWS metadata endpoints.
pub const DENY_RANGES: &[&str] = &[
    "169.254.169.254/32", // IMDS (IPv4)
    "fd00:ec2::254/128",  // IMDSv2 (IPv6)
    "169.254.170.2/32",   // ECS task metadata
];

/// Tier 4a: Internal DNS suffixes to deny.
pub const DENIED_DOMAIN_SUFFIXES: &[&str] = &[".internal", ".compute.internal", ".ec2.internal"];

/// Tier 4b: AWS service domain suffixes (for trusted-domain allow usage).
pub const SERVICE_DOMAIN_SUFFIXES: &[&str] = &[".amazonaws.com"];
