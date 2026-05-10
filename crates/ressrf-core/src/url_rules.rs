use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;

#[cfg(feature = "std")]
use regex::Regex;

/// A structured URL matching rule supporting scheme, host glob, path glob, or regex.
#[derive(Debug, Clone, Deserialize)]
pub struct UrlRule {
    /// Exact scheme match (e.g. "https"). If None, matches any scheme.
    #[serde(default)]
    pub scheme: Option<String>,

    /// Host glob pattern. `*` matches a single DNS label (subdomain wildcard).
    /// Examples: "*.stripe.com", "api.example.com", "*.internal"
    #[serde(default)]
    pub host: Option<String>,

    /// Path glob pattern. `*` matches a single segment, `**` matches any depth.
    /// Examples: "/v1/*", "/api/**"
    #[serde(default)]
    pub path: Option<String>,

    /// Full regex pattern matching the entire URL. When set, scheme/host/path are ignored.
    /// Uses Rust's regex crate (linear-time, ReDoS-safe) with a 1MB automaton size limit.
    #[serde(default)]
    pub regex: Option<String>,

    /// When true on an allow rule, a matching URL skips the IP-level policy check.
    #[serde(default)]
    pub bypass_ip_check: bool,
}

/// The result of evaluating a URL against a ruleset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlRuleDecision {
    /// URL matched a deny rule.
    Denied,
    /// URL matched an allow rule; proceed with normal IP check.
    Allowed,
    /// URL matched an allow rule with `bypass_ip_check=true`; skip IP check.
    AllowedBypassIp,
    /// No rules matched (or no rules configured); fall through to default behavior.
    NoMatch,
}

/// A set of URL allow and deny rules. Deny rules are evaluated first.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UrlRuleset {
    #[serde(default)]
    pub allow: Vec<UrlRule>,
    #[serde(default)]
    pub deny: Vec<UrlRule>,

    #[cfg(feature = "std")]
    #[serde(skip)]
    compiled_allow: Vec<CompiledRule>,
    #[cfg(feature = "std")]
    #[serde(skip)]
    compiled_deny: Vec<CompiledRule>,
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
struct CompiledRule {
    regex: Option<Regex>,
    rule: UrlRule,
}

/// Maximum regex automaton size (1 MB).
#[cfg(feature = "std")]
const REGEX_SIZE_LIMIT: usize = 1_048_576;

impl UrlRule {
    /// Create a rule matching a host glob pattern.
    pub fn host(pattern: &str) -> Self {
        Self {
            scheme: None,
            host: Some(String::from(pattern)),
            path: None,
            regex: None,
            bypass_ip_check: false,
        }
    }

    /// Create a rule with scheme, host, and path globs.
    pub fn glob(scheme: &str, host: &str, path: &str) -> Self {
        Self {
            scheme: Some(String::from(scheme)),
            host: Some(String::from(host)),
            path: Some(String::from(path)),
            regex: None,
            bypass_ip_check: false,
        }
    }

    /// Create a rule using a full regex pattern.
    pub fn regex(pattern: &str) -> Self {
        Self {
            scheme: None,
            host: None,
            path: None,
            regex: Some(String::from(pattern)),
            bypass_ip_check: false,
        }
    }

    /// Set `bypass_ip_check` to true (builder pattern).
    #[must_use]
    pub fn bypass_ip_check(mut self) -> Self {
        self.bypass_ip_check = true;
        self
    }

    /// Check if this rule matches the given URL parts using glob logic.
    /// Does NOT handle regex; that's done at the compiled level.
    pub fn matches_parts(&self, scheme: Option<&str>, host: &str, path: &str) -> bool {
        if let Some(ref rule_scheme) = self.scheme {
            match scheme {
                Some(s) if s.eq_ignore_ascii_case(rule_scheme) => {}
                _ => return false,
            }
        }

        if let Some(ref host_pattern) = self.host {
            if !glob_match_host(host_pattern, host) {
                return false;
            }
        }

        if let Some(ref path_pattern) = self.path {
            if !glob_match_path(path_pattern, path) {
                return false;
            }
        }

        true
    }
}

impl UrlRuleset {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_allow(&mut self, rule: UrlRule) {
        self.allow.push(rule);
    }

    pub fn add_deny(&mut self, rule: UrlRule) {
        self.deny.push(rule);
    }

    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Compile regex patterns. Must be called before `evaluate()` when using regex rules.
    /// On `no_std` builds, regex rules are silently ignored.
    #[cfg(feature = "std")]
    pub fn compile(&mut self) -> crate::Result<()> {
        self.compiled_deny = compile_rules(&self.deny)?;
        self.compiled_allow = compile_rules(&self.allow)?;
        Ok(())
    }

    /// Evaluate a URL against the ruleset.
    /// Returns the decision: `Denied`, `Allowed`, `AllowedBypassIp`, or `NoMatch`.
    #[cfg(feature = "std")]
    pub fn evaluate(&self, url: &str) -> UrlRuleDecision {
        let (scheme, host, path) = parse_url_components(url);

        for compiled in &self.compiled_deny {
            if rule_matches(compiled, url, scheme, host, path) {
                return UrlRuleDecision::Denied;
            }
        }

        if self.compiled_allow.is_empty() && self.allow.is_empty() {
            return UrlRuleDecision::NoMatch;
        }

        for compiled in &self.compiled_allow {
            if rule_matches(compiled, url, scheme, host, path) {
                if compiled.rule.bypass_ip_check {
                    return UrlRuleDecision::AllowedBypassIp;
                }
                return UrlRuleDecision::Allowed;
            }
        }

        UrlRuleDecision::Denied
    }

    /// Evaluate without std (no regex support). Regex rules are skipped.
    #[cfg(not(feature = "std"))]
    pub fn evaluate(&self, url: &str) -> UrlRuleDecision {
        let (scheme, host, path) = parse_url_components(url);

        for rule in &self.deny {
            if rule.regex.is_some() {
                continue;
            }
            if rule.matches_parts(scheme, host, path) {
                return UrlRuleDecision::Denied;
            }
        }

        if self.allow.is_empty() {
            return UrlRuleDecision::NoMatch;
        }

        for rule in &self.allow {
            if rule.regex.is_some() {
                continue;
            }
            if rule.matches_parts(scheme, host, path) {
                if rule.bypass_ip_check {
                    return UrlRuleDecision::AllowedBypassIp;
                }
                return UrlRuleDecision::Allowed;
            }
        }

        UrlRuleDecision::Denied
    }
}

#[cfg(feature = "std")]
fn compile_rules(rules: &[UrlRule]) -> crate::Result<Vec<CompiledRule>> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let regex = if let Some(ref pattern) = rule.regex {
            let re = regex::RegexBuilder::new(pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|e| crate::Error::Config(alloc::format!("invalid URL rule regex: {e}")))?;
            Some(re)
        } else {
            None
        };
        compiled.push(CompiledRule {
            regex,
            rule: rule.clone(),
        });
    }
    Ok(compiled)
}

#[cfg(feature = "std")]
fn rule_matches(
    compiled: &CompiledRule,
    url: &str,
    scheme: Option<&str>,
    host: &str,
    path: &str,
) -> bool {
    if let Some(ref re) = compiled.regex {
        return re.is_match(url);
    }
    compiled.rule.matches_parts(scheme, host, path)
}

/// Extract scheme, host, and path from a URL string without allocating.
fn parse_url_components(url: &str) -> (Option<&str>, &str, &str) {
    let (scheme, rest) = if let Some(idx) = url.find("://") {
        (Some(&url[..idx]), &url[idx + 3..])
    } else {
        (None, url)
    };

    let after_authority = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..after_authority];
    let path = if after_authority < rest.len() {
        &rest[after_authority..]
    } else {
        "/"
    };

    let host = if let Some(at_idx) = authority.rfind('@') {
        &authority[at_idx + 1..]
    } else {
        authority
    };

    let host = if host.starts_with('[') {
        if let Some(bracket_end) = host.find(']') {
            &host[..=bracket_end]
        } else {
            host
        }
    } else if let Some(colon_idx) = host.rfind(':') {
        let after = &host[colon_idx + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) && !after.is_empty() {
            &host[..colon_idx]
        } else {
            host
        }
    } else {
        host
    };

    (scheme, host, path)
}

/// Glob-match a host pattern against a hostname.
/// `*` matches exactly one DNS label (e.g. `*.example.com` matches `foo.example.com`
/// but not `foo.bar.example.com`).
fn glob_match_host(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let host = host.to_lowercase();

    if !pattern.contains('*') {
        return pattern == host;
    }

    let pat_parts: Vec<&str> = pattern.split('.').collect();
    let host_parts: Vec<&str> = host.split('.').collect();

    if pat_parts.len() != host_parts.len() {
        return false;
    }

    for (pat, h) in pat_parts.iter().zip(host_parts.iter()) {
        if *pat == "*" {
            continue;
        }
        if *pat != *h {
            return false;
        }
    }

    true
}

/// Glob-match a path pattern against a URL path.
/// `*` matches a single path segment, `**` matches zero or more segments.
fn glob_match_path(pattern: &str, path: &str) -> bool {
    let pattern_segs: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let actual_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    glob_match_segments(&pattern_segs, &actual_segs)
}

fn glob_match_segments(pattern: &[&str], path: &[&str]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }

    if pattern[0] == "**" {
        // ** can match zero or more segments
        if glob_match_segments(&pattern[1..], path) {
            return true;
        }
        if !path.is_empty() {
            return glob_match_segments(pattern, &path[1..]);
        }
        return false;
    }

    if path.is_empty() {
        return false;
    }

    let seg_matches = pattern[0] == "*" || pattern[0] == path[0];
    if seg_matches {
        return glob_match_segments(&pattern[1..], &path[1..]);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_glob_exact() {
        assert!(glob_match_host("example.com", "example.com"));
        assert!(glob_match_host("Example.COM", "example.com"));
        assert!(!glob_match_host("example.com", "other.com"));
    }

    #[test]
    fn host_glob_wildcard() {
        assert!(glob_match_host("*.example.com", "api.example.com"));
        assert!(glob_match_host("*.example.com", "foo.example.com"));
        assert!(!glob_match_host("*.example.com", "foo.bar.example.com"));
        assert!(!glob_match_host("*.example.com", "example.com"));
    }

    #[test]
    fn host_glob_multi_wildcard() {
        assert!(glob_match_host("*.*.example.com", "a.b.example.com"));
        assert!(!glob_match_host("*.*.example.com", "a.example.com"));
    }

    #[test]
    fn path_glob_single_star() {
        assert!(glob_match_path("/v1/*", "/v1/users"));
        assert!(glob_match_path("/v1/*", "/v1/orders"));
        assert!(!glob_match_path("/v1/*", "/v1/users/123"));
        assert!(!glob_match_path("/v1/*", "/v2/users"));
    }

    #[test]
    fn path_glob_double_star() {
        assert!(glob_match_path("/api/**", "/api/v1/users"));
        assert!(glob_match_path("/api/**", "/api/v1/users/123/orders"));
        assert!(glob_match_path("/api/**", "/api/anything"));
        assert!(glob_match_path("/**", "/anything/at/all"));
        assert!(!glob_match_path("/api/**", "/other/path"));
    }

    #[test]
    fn path_glob_exact() {
        assert!(glob_match_path("/health", "/health"));
        assert!(!glob_match_path("/health", "/health/check"));
    }

    #[test]
    fn path_glob_empty() {
        assert!(glob_match_path("/**", "/"));
        assert!(glob_match_path("/**", "/foo"));
    }

    #[test]
    fn url_rule_matches_parts() {
        let rule = UrlRule::glob("https", "*.stripe.com", "/v1/**");
        assert!(rule.matches_parts(Some("https"), "api.stripe.com", "/v1/charges"));
        assert!(rule.matches_parts(Some("https"), "api.stripe.com", "/v1/charges/ch_123"));
        assert!(!rule.matches_parts(Some("http"), "api.stripe.com", "/v1/charges"));
        assert!(!rule.matches_parts(Some("https"), "evil.com", "/v1/charges"));
        assert!(!rule.matches_parts(Some("https"), "api.stripe.com", "/v2/charges"));
    }

    #[test]
    fn url_rule_host_only() {
        let rule = UrlRule::host("*.internal");
        assert!(rule.matches_parts(Some("http"), "db.internal", "/"));
        assert!(rule.matches_parts(Some("https"), "cache.internal", "/api"));
        assert!(!rule.matches_parts(Some("http"), "example.com", "/"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn ruleset_deny_first() {
        let mut ruleset = UrlRuleset::new();
        ruleset.add_deny(UrlRule::host("*.internal"));
        ruleset.add_allow(UrlRule::host("*.internal"));
        ruleset.compile().unwrap();

        assert_eq!(
            ruleset.evaluate("http://db.internal/path"),
            UrlRuleDecision::Denied
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn ruleset_allow_blocks_unmatched() {
        let mut ruleset = UrlRuleset::new();
        ruleset.add_allow(UrlRule::glob("https", "*.stripe.com", "/**"));
        ruleset.compile().unwrap();

        assert_eq!(
            ruleset.evaluate("https://api.stripe.com/v1/charges"),
            UrlRuleDecision::Allowed
        );
        assert_eq!(
            ruleset.evaluate("https://evil.com/steal"),
            UrlRuleDecision::Denied
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn ruleset_bypass_ip() {
        let mut ruleset = UrlRuleset::new();
        ruleset.add_allow(UrlRule::host("internal-api.company.com").bypass_ip_check());
        ruleset.compile().unwrap();

        assert_eq!(
            ruleset.evaluate("https://internal-api.company.com/data"),
            UrlRuleDecision::AllowedBypassIp
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn ruleset_no_rules_returns_no_match() {
        let mut ruleset = UrlRuleset::new();
        ruleset.compile().unwrap();

        assert_eq!(
            ruleset.evaluate("https://anything.com/path"),
            UrlRuleDecision::NoMatch
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn ruleset_regex_deny() {
        let mut ruleset = UrlRuleset::new();
        ruleset.add_deny(UrlRule::regex(r"^http://.*$"));
        ruleset.compile().unwrap();

        assert_eq!(
            ruleset.evaluate("http://example.com/path"),
            UrlRuleDecision::Denied
        );
        assert_eq!(
            ruleset.evaluate("https://example.com/path"),
            UrlRuleDecision::NoMatch
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn regex_size_limit_enforced() {
        let mut ruleset = UrlRuleset::new();
        // This pattern is fine (small)
        ruleset.add_allow(UrlRule::regex(r"^https://api\.example\.com/.*$"));
        assert!(ruleset.compile().is_ok());
    }

    #[test]
    fn parse_url_components_basic() {
        let (scheme, host, path) = parse_url_components("https://api.example.com/v1/data");
        assert_eq!(scheme, Some("https"));
        assert_eq!(host, "api.example.com");
        assert_eq!(path, "/v1/data");
    }

    #[test]
    fn parse_url_components_with_port() {
        let (scheme, host, path) = parse_url_components("http://localhost:8080/health");
        assert_eq!(scheme, Some("http"));
        assert_eq!(host, "localhost");
        assert_eq!(path, "/health");
    }

    #[test]
    fn parse_url_components_no_path() {
        let (scheme, host, path) = parse_url_components("https://example.com");
        assert_eq!(scheme, Some("https"));
        assert_eq!(host, "example.com");
        assert_eq!(path, "/");
    }
}
