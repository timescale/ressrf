use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::cidr::{is_ambiguous_ip, is_ip_literal};
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

    /// Load domain suffixes from a cloud provider module.
    ///
    /// Adds the provider's internal DNS suffixes to the denied list and its
    /// service domain suffixes to the trusted list.
    pub fn with_cloud_provider(&mut self, provider: crate::cloud::CloudProvider) -> &mut Self {
        self.add_denied_suffixes(provider.denied_domain_suffixes());
        self.add_trusted_suffixes(provider.service_domain_suffixes());
        self
    }

    /// Validate a URL string. Returns Ok(()) if it passes all checks.
    ///
    /// Checks performed:
    /// 1. URL parsing (rejects UNC paths `\\host`, embedded NUL/CR/LF in host,
    ///    normalizes backslash to slash before authority extraction)
    /// 2. Scheme is required and must be in the allowlist (rejects scheme-less
    ///    URLs like `javascript:...`, `data:...`, `http:host/path`)
    /// 3. Trailing dot stripped from host before all other host-based checks
    /// 4. Ambiguous IP encoding detection (decimal/octal/hex/shorthand IPv4)
    /// 5. Bare IP detection (run through address check before further validation)
    /// 6. Userinfo bypass resistance (detect %40 confusion)
    /// 7. Hostname validation (IDN, double-dash, domain suffix matching)
    pub fn validate_url(&self, url: &str, policy: Option<&Policy>) -> crate::Result<()> {
        let url = url.trim();

        // 1. Parse URL components manually to avoid depending on the `url` crate in no_std.
        //    parse_url_parts handles BS-3 (NUL/CRLF), BS-5 (backslash), BS-6 (UNC).
        let parts = parse_url_parts(url)?;

        // 2. Scheme validation (BS-2): scheme is required, must be in the allowlist.
        if let Some(ref scheme) = parts.scheme {
            let scheme_lower = scheme.to_lowercase();
            if !self.allowed_schemes.contains(&scheme_lower) {
                return Err(Error::Blocked(DenyReason::SchemeNotAllowed {
                    scheme: scheme_lower,
                }));
            }
        } else {
            // Scheme-less URLs are rejected. Two cases:
            // - `javascript:alert(1)`, `data:text/html,...`, `http:host/path`
            //   (have a `:` but no `//`): treat the prefix as a non-allowed scheme.
            // - bare hostnames or paths: reject with SchemeRequired.
            if let Some(pseudo) = pseudo_scheme(url) {
                return Err(Error::Blocked(DenyReason::SchemeNotAllowed {
                    scheme: pseudo.to_lowercase(),
                }));
            }
            return Err(Error::Blocked(DenyReason::SchemeRequired));
        }

        // 3. Strip trailing dot (BS-4): treat `example.com.` as `example.com`.
        let host_normalized = parts.host.trim_end_matches('.');
        if host_normalized.is_empty() {
            return Err(Error::Blocked(DenyReason::UrlParseError {
                detail: String::from("empty host after stripping trailing dot"),
            }));
        }

        // 4. Ambiguous IP encoding detection (BS-1): octal/hex/decimal/shorthand
        //    IPv4 forms must be rejected before reaching DNS.
        if is_ambiguous_ip(host_normalized) {
            return Err(Error::Blocked(DenyReason::AmbiguousIpEncoding {
                host: String::from(host_normalized),
                form: String::from("non-canonical IPv4 (octal/hex/decimal/shorthand)"),
            }));
        }

        // 5. Bare IP detection: if host is an IP literal, validate it against policy first.
        if is_ip_literal(host_normalized) {
            if let Some(policy) = policy {
                let ip = parse_host_as_ip(host_normalized)?;
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

        // 6. Userinfo bypass: detect %40 in the authority before the actual host.
        if has_userinfo_bypass(url) {
            return Err(Error::Blocked(DenyReason::UserinfoBypassAttempt));
        }

        // 7. Hostname validation
        let host_lower = host_normalized.to_lowercase();

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
        if !self.trusted_domain_suffixes.is_empty() && !is_ip_literal(host_normalized) {
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
        let host_lower = host.trim_end_matches('.').to_lowercase();
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

    // BS-6: Reject UNC-style paths (`\\host\share`). These have no scheme
    // separator and can be interpreted as Windows file shares by some HTTP
    // stacks.
    if url.starts_with("\\\\") {
        return Err(Error::Blocked(DenyReason::UrlParseError {
            detail: String::from("UNC-style path not allowed"),
        }));
    }

    // BS-5: Normalize backslashes to forward slashes before authority
    // extraction. This prevents parser differential attacks where the URI
    // validator sees one host but the HTTP client interprets `\` as `/` and
    // connects to a different host. We do this on a working copy (after
    // splitting off the scheme) so the original scheme separator `://` is
    // unaffected.
    //
    // BS-3: Reject embedded NUL/CR/LF/percent-encoded NUL/CRLF early. Doing
    // it before scheme split catches CRLF in the scheme too.
    if has_prohibited_control_chars(url) {
        return Err(Error::Blocked(DenyReason::HostnameInvalid {
            reason: String::from("URL contains prohibited control characters (NUL/CR/LF)"),
        }));
    }

    // Extract scheme
    let (scheme, rest_owned) = if let Some(idx) = url.find("://") {
        let scheme = &url[..idx];
        let rest = &url[idx + 3..];
        // BS-5: backslash -> slash normalization in the post-scheme part only.
        let rest_normalized = rest.replace('\\', "/");
        (Some(String::from(scheme)), rest_normalized)
    } else {
        // No `://`. Still normalize backslashes for the rare case of
        // protocol-relative-style inputs that reach here.
        (None, url.replace('\\', "/"))
    };

    let rest = rest_owned.as_str();

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

    // BS-3 (defence-in-depth): re-check the extracted host for any
    // surviving control characters or percent-encoded NUL/CRLF.
    if host_has_prohibited_chars(host) {
        return Err(Error::Blocked(DenyReason::HostnameInvalid {
            reason: String::from("host contains prohibited control characters (NUL/CR/LF)"),
        }));
    }

    Ok(UrlParts {
        scheme,
        host: String::from(host),
    })
}

/// Detect raw control bytes anywhere in a URL string.
fn has_prohibited_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n')
}

/// Detect prohibited characters in an extracted host component.
/// Includes raw NUL/CR/LF as well as percent-encoded forms `%00`, `%0d`, `%0a`.
fn host_has_prohibited_chars(host: &str) -> bool {
    if has_prohibited_control_chars(host) {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    lower.contains("%00") || lower.contains("%0d") || lower.contains("%0a")
}

/// Extract the pseudo-scheme from a URL that has a `:` before any `/` but no `://`.
/// Used for BS-2 to reject `javascript:alert(1)`, `data:text/html,...`,
/// `http:host/path`. Returns `None` if the URL has no `:` before the first `/`.
fn pseudo_scheme(url: &str) -> Option<&str> {
    let colon_idx = url.find(':')?;
    let slash_idx = url.find('/');
    match slash_idx {
        Some(s) if s < colon_idx => None,
        _ => {
            let candidate = &url[..colon_idx];
            // A scheme per RFC 3986 begins with ALPHA and consists of
            // ALPHA / DIGIT / "+" / "-" / ".". Reject empty.
            if candidate.is_empty() {
                return None;
            }
            let first = candidate.as_bytes()[0];
            if !first.is_ascii_alphabetic() {
                return None;
            }
            if candidate
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
            {
                Some(candidate)
            } else {
                None
            }
        }
    }
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
///
/// BS-4: Both `host` and `suffix` are normalized by stripping any trailing dot
/// so `metadata.google.internal.` matches the suffix `google.internal`.
fn domain_matches_suffix(host: &str, suffix: &str) -> bool {
    let host = host.trim_end_matches('.');
    let suffix = suffix.trim_end_matches('.');
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
///
/// Uses the strict parser from `cidr.rs` which rejects octal, hex, and
/// shorthand IPv4 forms. Ambiguous forms must be detected with
/// `crate::cidr::is_ambiguous_ip` before reaching this function.
fn parse_host_as_ip(host: &str) -> crate::Result<IpAddr> {
    let inner = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    crate::cidr::parse_ip(inner)
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
        // file:/// has scheme `file` not in allowlist; rejected with SchemeNotAllowed
        // before the empty-host check now (consistent with other disallowed schemes).
        assert!(v.validate_url("file:///etc/passwd", None).is_err());
    }

    // ---------- Blind spot fixes ----------

    #[test]
    fn bs1_ambiguous_decimal_ip_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://2130706433/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::AmbiguousIpEncoding { .. })
        ));
    }

    #[test]
    fn bs1_ambiguous_octal_ip_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://0177.0.0.1/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::AmbiguousIpEncoding { .. })
        ));
    }

    #[test]
    fn bs1_ambiguous_hex_ip_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://0x7f000001/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::AmbiguousIpEncoding { .. })
        ));
        let result = v.validate_url("http://0x7f.0.0.1/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::AmbiguousIpEncoding { .. })
        ));
    }

    #[test]
    fn bs1_ambiguous_shorthand_ip_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://127.1/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::AmbiguousIpEncoding { .. })
        ));
    }

    #[test]
    fn bs2_javascript_url_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("javascript:alert(1)", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::SchemeNotAllowed { .. })
        ));
    }

    #[test]
    fn bs2_data_url_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("data:text/html,<script>alert(1)</script>", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::SchemeNotAllowed { .. })
        ));
    }

    #[test]
    fn bs2_http_without_double_slash_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http:host/path", None);
        // `http:host/path` is treated as scheme `http` with no `//` separator;
        // the pseudo-scheme detector reports it as SchemeNotAllowed.
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::SchemeNotAllowed { .. })
        ));
    }

    #[test]
    fn bs2_bare_hostname_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("example.com", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::SchemeRequired)
        ));
    }

    #[test]
    fn bs3_null_byte_in_host_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://evil.com%00.trusted.com/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::HostnameInvalid { .. })
        ));
    }

    #[test]
    fn bs3_crlf_in_url_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("http://example.com%0d%0aHost:%20169.254.169.254", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::HostnameInvalid { .. })
        ));
    }

    #[test]
    fn bs3_raw_nul_in_url_rejected() {
        let v = UriValidator::new();
        let bad = "http://example\0.com/";
        let result = v.validate_url(bad, None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::HostnameInvalid { .. })
        ));
    }

    #[test]
    fn bs4_trailing_dot_does_not_bypass_suffix_deny() {
        let mut v = UriValidator::new();
        v.add_denied_suffixes(&["google.internal"]);

        // Without the fix, the trailing dot would bypass the suffix match.
        let result = v.validate_url("http://metadata.google.internal./", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::DomainSuffixDenied { .. })
        ));
    }

    #[test]
    fn bs4_trailing_dot_in_suffix_normalized() {
        let mut v = UriValidator::new();
        // Suffix configured with a trailing dot should still match canonical hosts.
        v.add_denied_suffixes(&["google.internal."]);

        let result = v.validate_url("http://metadata.google.internal/", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::DomainSuffixDenied { .. })
        ));
    }

    #[test]
    fn bs5_backslash_userinfo_bypass_rejected() {
        // `http://trusted.com\@evil.com/` -- some HTTP clients parse `\` as `/`.
        // With backslash normalized to `/`, the host becomes `trusted.com`,
        // followed by `/@evil.com`. The userinfo bypass detector then flags
        // the `@` after the path-like prefix is gone.
        // The key property tested: the validator does NOT see `evil.com` as
        // the host (which would happen without normalization).
        let mut v = UriValidator::new();
        v.add_trusted_suffixes(&["trusted.com"]);
        // After normalization, host should be `trusted.com`, which is allowed.
        let result = v.validate_url("http://trusted.com\\@evil.com/", None);
        assert!(result.is_ok(), "got {result:?}");
    }

    #[test]
    fn bs5_backslash_to_internal_ip_normalized() {
        // `http://127.0.0.1\@trusted.com/` should resolve to host `127.0.0.1`
        // after normalization, blocking on bare-IP IMDS/loopback policy.
        let policy = PolicyBuilder::external_only().build();
        let v = UriValidator::new();
        let result = v.validate_url("http://127.0.0.1\\@trusted.com/", Some(&policy));
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::BareIpDeniedBeforeScheme { .. })
        ));
    }

    #[test]
    fn bs6_unc_path_rejected() {
        let v = UriValidator::new();
        let result = v.validate_url("\\\\evil.com\\share", None);
        assert!(matches!(
            result.unwrap_err(),
            Error::Blocked(DenyReason::UrlParseError { .. })
        ));
    }

    #[test]
    fn bs6_protocol_relative_url_rejected() {
        let v = UriValidator::new();
        // `//127.0.0.1/` has an empty authority before the host (since `//`
        // is the separator and the host is empty after splitting on `/`)
        // -> rejected as SchemeRequired (no scheme) or empty host.
        let result = v.validate_url("//127.0.0.1/", None);
        assert!(result.is_err());
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
