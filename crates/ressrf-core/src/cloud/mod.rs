//! Cloud provider modules providing SSRF deny ranges and domain suffixes.
//!
//! Each module exposes:
//! - `DENY_RANGES`: IP ranges to block (metadata endpoints)
//! - `DENIED_DOMAIN_SUFFIXES`: internal DNS suffixes to reject
//! - `SERVICE_DOMAIN_SUFFIXES`: legitimate service domains for allow-listing

pub mod aws;
pub mod azure;
pub mod gcp;

#[cfg(test)]
#[path = "tests.rs"]
mod cloud_tests;

/// Supported cloud providers for convenience loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl CloudProvider {
    /// Get the deny ranges for this provider.
    #[must_use]
    pub fn deny_ranges(self) -> &'static [&'static str] {
        match self {
            Self::Aws => aws::DENY_RANGES,
            Self::Azure => azure::DENY_RANGES,
            Self::Gcp => gcp::DENY_RANGES,
        }
    }

    /// Get internal DNS suffixes that should be denied.
    #[must_use]
    pub fn denied_domain_suffixes(self) -> &'static [&'static str] {
        match self {
            Self::Aws => aws::DENIED_DOMAIN_SUFFIXES,
            Self::Azure => azure::DENIED_DOMAIN_SUFFIXES,
            Self::Gcp => gcp::DENIED_DOMAIN_SUFFIXES,
        }
    }

    /// Get legitimate service domain suffixes for allow-listing.
    #[must_use]
    pub fn service_domain_suffixes(self) -> &'static [&'static str] {
        match self {
            Self::Aws => aws::SERVICE_DOMAIN_SUFFIXES,
            Self::Azure => azure::SERVICE_DOMAIN_SUFFIXES,
            Self::Gcp => gcp::SERVICE_DOMAIN_SUFFIXES,
        }
    }

    /// Provider name as used in audit events and logging.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
        }
    }
}
