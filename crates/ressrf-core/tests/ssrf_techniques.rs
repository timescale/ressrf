//! Integration test runner for the shared SSRF technique vectors.
//!
//! Loads `tests/vectors/ssrf_techniques.json` and runs every case through
//! `UriValidator::validate_url` with a default `ExternalOnly` policy.
//!
//! Each case can override:
//! - `denied_suffixes`: list of denied domain suffixes
//! - `trusted_suffixes`: list of trusted domain suffixes (allowlist)
//!
//! And asserts:
//! - `expected`: `"allowed"` or `"blocked"`
//! - `reason_type` (optional): the `snake_case` `DenyReason::type` tag the
//!   validator should emit when blocked; verified via serde-tagged JSON
//!
//! This is a Tier 1 (URL-level, no network) test runner. Tier 2 e2e tests
//! that need DNS/HTTP live in `crates/ressrf-tcp/tests/ssrf_e2e.rs`.

use std::path::PathBuf;

use ressrf_core::error::{DenyReason, Error};
use ressrf_core::policy::PolicyBuilder;
use ressrf_core::uri_validator::UriValidator;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("vectors")
        .join("ssrf_techniques.json")
}

fn deny_reason_tag(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::UrlParseError { .. } => "url_parse_error",
        DenyReason::SchemeNotAllowed { .. } => "scheme_not_allowed",
        DenyReason::SchemeRequired => "scheme_required",
        DenyReason::BareIpDeniedBeforeScheme { .. } => "bare_ip_denied_before_scheme",
        DenyReason::HostnameInvalid { .. } => "hostname_invalid",
        DenyReason::AmbiguousIpEncoding { .. } => "ambiguous_ip_encoding",
        DenyReason::IdnError { .. } => "idn_error",
        DenyReason::UserinfoBypassAttempt => "userinfo_bypass_attempt",
        DenyReason::DomainNotInAllowList { .. } => "domain_not_in_allow_list",
        DenyReason::DomainSuffixDenied { .. } => "domain_suffix_denied",
        DenyReason::DnsResolveFailed { .. } => "dns_resolve_failed",
        DenyReason::DnsEmptyResponse { .. } => "dns_empty_response",
        DenyReason::AllResolvedIpsDenied { .. } => "all_resolved_ips_denied",
        DenyReason::InDenyCidr { .. } => "in_deny_cidr",
        DenyReason::NotInAllowList { .. } => "not_in_allow_list",
        DenyReason::MultiHostFallbackDenied { .. } => "multi_host_fallback_denied",
        DenyReason::RequiredHeaderMissing { .. } => "required_header_missing",
        DenyReason::DeniedHeaderPresent { .. } => "denied_header_present",
        DenyReason::RedirectSchemeDowngrade { .. } => "redirect_scheme_downgrade",
        DenyReason::RedirectHostChanged { .. } => "redirect_host_changed",
        DenyReason::RedirectHopDenied { .. } => "redirect_hop_denied",
        DenyReason::ProtocolNotAllowed { .. } => "protocol_not_allowed",
        DenyReason::PlaintextHttpDenied => "plaintext_http_denied",
        DenyReason::UrlRuleDenied { .. } => "url_rule_denied",
        DenyReason::UrlRuleNotInAllowList { .. } => "url_rule_not_in_allow_list",
        DenyReason::ExplicitDenyList { .. } => "explicit_deny_list",
        DenyReason::PolicyImmutabilityViolation => "policy_immutability_violation",
    }
}

#[test]
fn ssrf_techniques_vectors() {
    let path = vectors_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    let data: serde_json::Value =
        serde_json::from_str(&content).expect("ssrf_techniques.json is not valid JSON");

    let policy = PolicyBuilder::external_only().build();

    let cases = data["cases"]
        .as_array()
        .expect("ssrf_techniques.json missing top-level `cases` array");

    let mut failures: Vec<String> = Vec::new();

    for case in cases {
        let name = case["name"].as_str().expect("case missing `name`");
        let url = case["url"].as_str().expect("case missing `url`");
        let category = case["category"].as_str().unwrap_or("uncategorized");
        let expected = case["expected"].as_str().expect("case missing `expected`");
        let expected_reason = case.get("reason_type").and_then(|v| v.as_str());

        let mut validator = UriValidator::new();
        if let Some(denied) = case.get("denied_suffixes").and_then(|v| v.as_array()) {
            let suffixes: Vec<&str> = denied.iter().map(|v| v.as_str().unwrap()).collect();
            validator.add_denied_suffixes(&suffixes);
        }
        if let Some(trusted) = case.get("trusted_suffixes").and_then(|v| v.as_array()) {
            let suffixes: Vec<&str> = trusted.iter().map(|v| v.as_str().unwrap()).collect();
            validator.add_trusted_suffixes(&suffixes);
        }

        let result = validator.validate_url(url, Some(&policy));

        match expected {
            "allowed" => {
                if let Err(e) = result {
                    failures.push(format!(
                        "[{category}] {name}: expected allowed for `{url}`, got {e:?}"
                    ));
                }
            }
            "blocked" => match result {
                Ok(()) => {
                    failures.push(format!(
                        "[{category}] {name}: expected blocked for `{url}`, got allowed"
                    ));
                }
                Err(Error::Blocked(reason)) => {
                    if let Some(want) = expected_reason {
                        let got = deny_reason_tag(&reason);
                        if got != want {
                            failures.push(format!(
                                "[{category}] {name}: expected reason `{want}`, got `{got}` for `{url}`"
                            ));
                        }
                    }
                }
                Err(Error::Parse(detail)) => {
                    if expected_reason.is_some() {
                        failures.push(format!(
                            "[{category}] {name}: expected DenyReason but got Parse({detail}) for `{url}`"
                        ));
                    }
                }
                Err(other) => {
                    failures.push(format!(
                        "[{category}] {name}: expected blocked for `{url}`, got non-Blocked error {other:?}"
                    ));
                }
            },
            other => panic!(
                "[{category}] {name}: unknown `expected` value `{other}`; must be allowed|blocked"
            ),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} ssrf_techniques cases failed:\n  - {}",
        failures.len(),
        cases.len(),
        failures.join("\n  - ")
    );
}
