//! GCP cloud module: metadata server deny ranges and domain suffixes.

/// Tier 2 deny ranges for GCP metadata.
pub const DENY_RANGES: &[&str] = &[
    "169.254.169.254/32", // GCP metadata server
];

/// Tier 4a: Internal DNS suffixes to deny.
pub const DENIED_DOMAIN_SUFFIXES: &[&str] = &[".internal", "metadata.google.internal"];

/// Tier 4b: GCP service domain suffixes (for trusted-domain allow usage).
pub const SERVICE_DOMAIN_SUFFIXES: &[&str] = &[".googleapis.com", ".run.app", ".appspot.com"];
