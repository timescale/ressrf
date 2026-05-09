use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::cidr::is_ip_literal;
use crate::error::{DenyReason, Error};
use crate::policy::Policy;

/// Allowed URI schemes.
const DEFAULT_ALLOWED_SCHEMES: &[&str] = &["http", "https", "ws", "wss"];

/// URI validator for string-only checks (no DNS, no connections).
/// Validates protocol allowlists, domain matching, bare IP detection, and userinfo bypass.
#[derive(Debug)]
pub struct UriValidator {
    allowed_schemes: Vec<String>,
    trusted_domain_suffixes: Vec<String>,
    denied_domain_suffixes: Vec<String>,
    reject_double_dash_hostnames: bool,
}

impl Default for UriValidator {
    fn default() -> Self {
        Self {
            allowed_schemes: DEFAULT_ALLOWED_SCHEMES
                .iter()
                .map(|&s| String::from(s))
                .collect(),
            trusted_domain_suffixes: Vec::new(),
            denied_domain_suffixes: Vec::new(),
            reject_double_dash_hostnames: true,
        }
    }
}

impl UriValidator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add trusted domain suffixes for allowlisting (e.g. "core.windows.net").
    pub fn add_trusted_suffixes(&mut self, suffixes: &[&str]) -> &mut Self {
        for &s in suffixes {
            self.trusted_domain_suffixes.push(s.to_lowercase());
        }
        self
    }

    /// Add denied domain suffixes (e.g. internal DNS suffixes like ".internal").
    pub fn add_denied_suffixes(&mut self, suffixes: &[&str]) -> &mut Self {
        for &s in suffixes {
            self.denied_domain_suffixes.push(s.to_lowercase());
        }
        self
    }

    /// Set whether to reject hostnames containing "--" (for cloud validator hardening).
    pub fn reject_double_dash(&mut self, reject: bool) -> &mut Self {
        self.reject_double_dash_hostnames = reject;
        self
    }

    /// Validate a URL string. Returns Ok(()) if it passes all checks.
    ///
    /// Checks performed:
    /// 1. Bare IP detection (run through address check before scheme validation)
    /// 2. Userinfo bypass resistance (detect %40 confusion)
    /// 3. Scheme allowlist
    /// 4. Hostname validation (IDN, double-dash, domain suffix matching)
    pub fn validate_url(&self, url: &str, policy: Option<&Policy>) -> crate::Result<()> {
        let url = url.trim();

        // Parse URL components manually to avoid depending on the `url` crate in no_std.
        let parts = parse_url_parts(url)?;

        // 1. Bare IP detection: if host is an IP literal, validate it against policy first.
        if is_ip_literal(&parts.host) {
            if let Some(policy) = policy {
                let ip = parse_host_as_ip(&parts.host)?;
                policy.is_network_allowed(&[ip]).map_err(|e| {
                    if let Error::Blocked(_) = e {
                        Error::Blocked(DenyReason::BareIpDeniedBeforeScheme {
                            ip: alloc::format!("{ip}"),
                        })
                    } else {
                        e
                    }
                })?;
            }
        }

        // 2. Userinfo bypass: detect %40 in the authority before the actual host.
        if has_userinfo_bypass(url) {
            return Err(Error::Blocked(DenyReason::UserinfoBypassAttempt));
        }

        // 3. Scheme allowlist
        if let Some(ref scheme) = parts.scheme {
            let scheme_lower = scheme.to_lowercase();
            if !self.allowed_schemes.contains(&scheme_lower) {
                return Err(Error::Blocked(DenyReason::SchemeNotAllowed {
                    scheme: scheme_lower,
                }));
            }
        }

        // 4. Hostname validation
        let host_lower = parts.host.to_lowercase();

        // Reject double-dash for cloud domain validators
        if self.reject_double_dash_hostnames && host_lower.contains("--") {
            // Allow "xn--" for punycode
            let has_non_punycode_dash = host_lower
                .split('.')
                .any(|label| label.contains("--") && !label.starts_with("xn--"));
            if has_non_punycode_dash {
                return Err(Error::Blocked(DenyReason::HostnameInvalid {
                    reason: String::from("hostname contains '--' (non-punycode)"),
                }));
            }
        }

        // Check denied domain suffixes
        for suffix in &self.denied_domain_suffixes {
            if domain_matches_suffix(&host_lower, suffix) {
                return Err(Error::Blocked(DenyReason::DomainSuffixDenied {
                    host: host_lower,
                    suffix: suffix.clone(),
                }));
            }
        }

        // If trusted suffixes are configured, host must match one of them
        if !self.trusted_domain_suffixes.is_empty() && !is_ip_literal(&parts.host) {
            let matches_trusted = self
                .trusted_domain_suffixes
                .iter()
                .any(|suffix| domain_matches_suffix(&host_lower, suffix));
            if !matches_trusted {
                return Err(Error::Blocked(DenyReason::DomainNotInAllowList {
                    host: host_lower,
                }));
            }
        }

        Ok(())
    }

    /// Check if a host matches any trusted domain suffix.
    #[must_use]
    pub fn is_trusted_domain(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        self.trusted_domain_suffixes
            .iter()
            .any(|suffix| domain_matches_suffix(&host_lower, suffix))
    }
}

/// Minimal URL parts extraction without depending on the `url` crate.
#[derive(Debug)]
struct UrlParts {
    scheme: Option<String>,
    host: String,
}

fn parse_url_parts(url: &str) -> crate::Result<UrlParts> {
    let url = url.trim();

    if url.is_empty() {
        return Err(Error::Blocked(DenyReason::UrlParseError {
            detail: String::from("empty URL"),
        }));
    }

    // Extract scheme
    let (scheme, rest) = if let Some(idx) = url.find("://") {
        let scheme = &url[..idx];
        let rest = &url[idx + 3..];
        (Some(String::from(scheme)), rest)
    } else {
        (None, url)
    };

    // Strip userinfo (everything before @ that is not percent-encoded)
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.split('?').next().unwrap_or(authority);
    let authority = authority.split('#').next().unwrap_or(authority);

    // Extract host from authority (after last unencoded @)
    let host_part = if let Some(at_idx) = authority.rfind('@') {
        &authority[at_idx + 1..]
    } else {
        authority
    };

    // Strip port
    let host = if host_part.starts_with('[') {
        // IPv6 bracket notation: [::1]:port
        if let Some(bracket_end) = host_part.find(']') {
            &host_part[..=bracket_end]
        } else {
            host_part
        }
    } else if let Some(colon_idx) = host_part.rfind(':') {
        // Only strip if what follows looks like a port number
        let after_colon = &host_part[colon_idx + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) && !after_colon.is_empty() {
            &host_part[..colon_idx]
        } else {
            host_part
        }
    } else {
        host_part
    };

    if host.is_empty() {
        return Err(Error::Blocked(DenyReason::UrlParseError {
            detail: String::from("empty host"),
        }));
    }

    Ok(UrlParts {
        scheme,
        host: String::from(host),
    })
}

/// Detect userinfo bypass attempts: URL-encoded `@` (`%40`) before the real host.
/// A URL like `http://user:p%40ss@169.254.169.254/` could trick parsers that split on `%40`.
fn has_userinfo_bypass(url: &str) -> bool {
    // Find the authority portion
    let rest = if let Some(idx) = url.find("://") {
        &url[idx + 3..]
    } else {
        url
    };

    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.split('?').next().unwrap_or(authority);
    let authority = authority.split('#').next().unwrap_or(authority);

    // If there is a real @ AND a %40 in the authority, this is suspicious
    if authority.contains('@') && authority.contains("%40") {
        return true;
    }

    // If there is a %40 that could be interpreted as a host separator
    if let Some(encoded_at_pos) = authority.find("%40") {
        // Check if the text after %40 looks like a host (contains a dot or colon)
        let after = &authority[encoded_at_pos + 3..];
        let after_host = if let Some(at_idx) = after.rfind('@') {
            &after[at_idx + 1..]
        } else {
            after
        };
        if after_host.contains('.') || after_host.contains(':') {
            return true;
        }
    }

    false
}

/// Boundary-aware domain suffix matching.
/// "api.core.windows.net" matches suffix "core.windows.net"
/// "notcore.windows.net" does NOT match suffix "core.windows.net"
fn domain_matches_suffix(host: &str, suffix: &str) -> bool {
    let suffix = suffix.strip_prefix('.').unwrap_or(suffix);
    if host == suffix {
        return true;
    }
    if host.ends_with(suffix) {
        let prefix_end = host.len() - suffix.len();
        if prefix_end > 0 {
            return host.as_bytes()[prefix_end - 1] == b'.';
        }
    }
    false
}

/// Parse a host string as an IP address, handling bracket notation.
fn parse_host_as_ip(host: &str) -> crate::Result<IpAddr> {
    let inner = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    inner
        .parse::<IpAddr>()
        .map_err(|e| Error::Parse(alloc::format!("failed to parse IP: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyBuilder;

    #[test]
    fn allowed_schemes() {
        let v = UriValidator::new();
        assert!(v.validate_url("https://example.com", None).is_ok());
        assert!(v.validate_url("http://example.com", None).is_ok());
        assert!(v.validate_url("ws://example.com", None).is_ok());
        assert!(v.validate_url("wss://example.com", None).is_ok());
    }

    #[test]
    fn disallowed_schemes() {
        let v = UriValidator::new();
        assert!(matches!(
            v.validate_url("ftp://example.com", None),
            Err(Error::Blocked(DenyReason::SchemeNotAllowed { .. }))
        ));
        assert!(matches!(
            v.validate_url("gopher://example.com", None),
            Err(Error::Blocked(DenyReason::SchemeNotAllowed { .. }))
        ));
        // file:/// has empty host which triggers UrlParseError first
        assert!(v.validate_url("file:///etc/passwd", None).is_err());
    }

    #[test]
    fn bare_ip_detection() {
        let policy = PolicyBuilder::external_only().build();
        let v = UriValidator::new();

        let result = v.validate_url("http://169.254.169.254/latest/meta-data/", Some(&policy));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::BareIpDeniedBeforeScheme { .. })
        ));
    }

    #[test]
    fn userinfo_bypass_detected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://user:p%40ss@169.254.169.254/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::UserinfoBypassAttempt)
        ));
    }

    #[test]
    fn userinfo_bypass_encoded_at() {
        let v = UriValidator::new();
        let result = v.validate_url("http://foo%40bar@169.254.169.254/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::UserinfoBypassAttempt)
        ));
    }

    #[test]
    fn domain_suffix_matching() {
        assert!(domain_matches_suffix(
            "api.core.windows.net",
            "core.windows.net"
        ));
        assert!(domain_matches_suffix(
            "core.windows.net",
            "core.windows.net"
        ));
        assert!(!domain_matches_suffix(
            "notcore.windows.net",
            "core.windows.net"
        ));
        assert!(!domain_matches_suffix(
            "fakecore.windows.net",
            "core.windows.net"
        ));
    }

    #[test]
    fn denied_domain_suffix() {
        let mut v = UriValidator::new();
        v.add_denied_suffixes(&[".internal", ".svc.cluster.local"]);

        assert!(matches!(
            v.validate_url("http://db.internal", None),
            Err(Error::Blocked(DenyReason::DomainSuffixDenied { .. }))
        ));
        assert!(matches!(
            v.validate_url("http://svc.default.svc.cluster.local", None),
            Err(Error::Blocked(DenyReason::DomainSuffixDenied { .. }))
        ));
    }

    #[test]
    fn trusted_domain_allowlist() {
        let mut v = UriValidator::new();
        v.add_trusted_suffixes(&["example.com", "trusted.io"]);

        assert!(v.validate_url("https://api.example.com/path", None).is_ok());
        assert!(v.validate_url("https://app.trusted.io", None).is_ok());
        assert!(matches!(
            v.validate_url("https://evil.com", None),
            Err(Error::Blocked(DenyReason::DomainNotInAllowList { .. }))
        ));
    }

    #[test]
    fn double_dash_rejected_non_punycode() {
        let v = UriValidator::new();
        assert!(matches!(
            v.validate_url("https://foo--bar.example.com", None),
            Err(Error::Blocked(DenyReason::HostnameInvalid { .. }))
        ));
    }

    #[test]
    fn punycode_double_dash_allowed() {
        let v = UriValidator::new();
        // xn-- is valid punycode prefix
        assert!(v
            .validate_url("https://xn--nxasmq6b.example.com", None)
            .is_ok());
    }

    #[test]
    fn empty_url_rejected() {
        let v = UriValidator::new();
        assert!(v.validate_url("", None).is_err());
    }
}
