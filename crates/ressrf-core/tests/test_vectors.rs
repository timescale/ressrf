//! Integration tests driven by shared JSON test vectors.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ressrf_core::audit::{AuditEvent, AuditSink, CollectingSink};
use ressrf_core::cidr::Cidr;
use ressrf_core::cloud::CloudProvider;
use ressrf_core::error::DataTier;
use ressrf_core::policy::{PolicyBuilder, Preset};
use ressrf_core::uri_validator::UriValidator;
use ressrf_core::url_rules::UrlRuleset;

struct ArcSink(Arc<CollectingSink>);

impl AuditSink for ArcSink {
    fn emit(&self, event: &AuditEvent) {
        self.0.emit(event);
    }
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("vectors")
}

#[test]
fn cidr_containment_vectors() {
    let path = vectors_dir().join("cidr_containment.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    for case in data["cases"].as_array().unwrap() {
        let cidr_str = case["cidr"].as_str().unwrap();
        let ip_str = case["ip"].as_str().unwrap();
        let expected = case["expected"].as_bool().unwrap();
        let note = case.get("note").and_then(|v| v.as_str()).unwrap_or("");

        let cidr = Cidr::parse(cidr_str, DataTier::Iana)
            .unwrap_or_else(|e| panic!("Failed to parse CIDR {cidr_str}: {e}"));
        let ip: IpAddr = ip_str
            .parse()
            .unwrap_or_else(|e| panic!("Failed to parse IP {ip_str}: {e}"));

        assert_eq!(
            cidr.contains(ip),
            expected,
            "CIDR {cidr_str} contains {ip_str}: expected {expected} ({note})"
        );
    }
}

#[test]
fn ipv4_ipv6_mapping_vectors() {
    let path = vectors_dir().join("ipv4_ipv6_mapping.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    for case in data["cases"].as_array().unwrap() {
        let ipv4_str = case["ipv4"].as_str().unwrap();
        let ipv6_mapped_str = case["ipv6_mapped"].as_str().unwrap();
        let cidr_str = case["cidr"].as_str().unwrap();
        let both_contained = case["both_contained"].as_bool().unwrap();
        let name = case["name"].as_str().unwrap();

        let cidr = Cidr::parse(cidr_str, DataTier::Iana).unwrap();
        let ipv4: IpAddr = ipv4_str.parse().unwrap();
        let ipv6_mapped: IpAddr = ipv6_mapped_str.parse().unwrap();

        assert_eq!(
            cidr.contains(ipv4),
            both_contained,
            "{name}: IPv4 {ipv4_str} in {cidr_str}"
        );
        assert_eq!(
            cidr.contains(ipv6_mapped),
            both_contained,
            "{name}: IPv6-mapped {ipv6_mapped_str} in {cidr_str}"
        );
    }
}

#[test]
fn policy_decision_vectors() {
    let path = vectors_dir().join("policy_decisions.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    for case in data["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let preset_str = case["preset"].as_str().unwrap();
        let ip_strs: Vec<&str> = case["ips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let expected = case["expected"].as_str().unwrap();

        let preset = match preset_str {
            "external_only" => Preset::ExternalOnly,
            "internal_only" => Preset::InternalOnly,
            "none" => Preset::None,
            _ => panic!("Unknown preset: {preset_str}"),
        };

        let mut builder = PolicyBuilder::new(preset);

        if let Some(allow_arr) = case.get("allow").and_then(|v| v.as_array()) {
            let allows: Vec<&str> = allow_arr.iter().map(|v| v.as_str().unwrap()).collect();
            builder.add_allowed(&allows);
        }

        if let Some(cloud_arr) = case.get("cloud_providers").and_then(|v| v.as_array()) {
            for provider_val in cloud_arr {
                let name = provider_val.as_str().unwrap();
                match name {
                    "aws" => builder.with_cloud(CloudProvider::Aws),
                    "azure" => builder.with_cloud(CloudProvider::Azure),
                    "gcp" => builder.with_cloud(CloudProvider::Gcp),
                    _ => panic!("Unknown cloud provider: {name}"),
                };
            }
        }

        let policy = builder.build();

        let ips: Vec<IpAddr> = ip_strs
            .iter()
            .map(|s| s.parse().unwrap_or_else(|e| panic!("Bad IP {s}: {e}")))
            .collect();

        let result = policy.is_network_allowed(&ips);

        match expected {
            "allowed" => assert!(
                result.is_ok(),
                "{name}: expected allowed, got {:?}",
                result.unwrap_err()
            ),
            "blocked" => assert!(result.is_err(), "{name}: expected blocked, got allowed"),
            _ => panic!("Unknown expected: {expected}"),
        }
    }
}

#[test]
fn url_validation_vectors() {
    let path = vectors_dir().join("url_validation.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    let policy = PolicyBuilder::external_only().build();

    for case in data["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let url = case["url"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();

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
            "allowed" => assert!(
                result.is_ok(),
                "{name}: expected allowed for URL '{url}', got {:?}",
                result.unwrap_err()
            ),
            "blocked" => assert!(
                result.is_err(),
                "{name}: expected blocked for URL '{url}', got allowed"
            ),
            _ => panic!("Unknown expected: {expected}"),
        }
    }
}

#[test]
fn url_rules_vectors() {
    let path = vectors_dir().join("url_rules.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    for case in data["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let url = case["url"].as_str().unwrap();
        let expected = case["expected"].as_str().unwrap();

        let preset_str = case
            .get("preset")
            .and_then(|v| v.as_str())
            .unwrap_or("external_only");
        let preset = match preset_str {
            "external_only" => Preset::ExternalOnly,
            "internal_only" => Preset::InternalOnly,
            "none" => Preset::None,
            _ => panic!("Unknown preset: {preset_str}"),
        };

        let mut builder = PolicyBuilder::new(preset);

        if let Some(url_rules) = case.get("url_rules") {
            let ruleset: UrlRuleset = serde_json::from_value(url_rules.clone()).unwrap_or_default();
            builder.url_ruleset(ruleset);
        }

        let policy = builder.try_build().unwrap_or_else(|e| {
            panic!("{name}: failed to build policy: {e}");
        });

        let result = policy.validate_url_rules(url);

        match expected {
            "allowed" => match result {
                Ok(_) => {}
                Err(e) => panic!("{name}: expected allowed for URL '{url}', got {e}"),
            },
            "blocked" => {
                assert!(
                    result.is_err(),
                    "{name}: expected blocked for URL '{url}', got allowed"
                );
            }
            _ => panic!("Unknown expected: {expected}"),
        }
    }
}

fn parse_preset(s: &str) -> Preset {
    match s {
        "external_only" => Preset::ExternalOnly,
        "internal_only" => Preset::InternalOnly,
        "none" => Preset::None,
        _ => panic!("Unknown preset: {s}"),
    }
}

#[test]
fn audit_event_vectors() {
    let path = vectors_dir().join("audit_events.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    for case in data["test_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let action = case["action"].as_str().unwrap();
        let config = &case["config"];

        match action {
            "create_policy" => {
                let preset_str = config["preset"].as_str().unwrap();
                let preset = parse_preset(preset_str);
                let sink = Arc::new(CollectingSink::new());

                let has_sink = !config.get("audit_sink").is_some_and(|v| v.is_null());

                if !has_sink {
                    let _policy = PolicyBuilder::new(preset).build();
                    // no_event_when_no_sink: nothing to assert, just verify no panic
                    continue;
                }

                let mut builder = PolicyBuilder::new(preset);
                if let Some(cloud_arr) = config.get("cloud_modules").and_then(|v| v.as_array()) {
                    for provider_val in cloud_arr {
                        let pname = provider_val.as_str().unwrap();
                        match pname {
                            "aws" => builder.with_cloud(CloudProvider::Aws),
                            "azure" => builder.with_cloud(CloudProvider::Azure),
                            "gcp" => builder.with_cloud(CloudProvider::Gcp),
                            _ => panic!("{name}: unknown cloud provider: {pname}"),
                        };
                    }
                }
                builder.audit_sink(Box::new(ArcSink(Arc::clone(&sink))));
                let _policy = builder.build();

                let events = sink.events();
                let expected = &case["expected_event"];
                let variant = expected["variant"].as_str().unwrap();
                assert_eq!(variant, "PolicyCreated", "{name}: expected PolicyCreated");
                assert!(
                    !events.is_empty(),
                    "{name}: expected at least one audit event"
                );

                let created = events
                    .iter()
                    .find(|e| matches!(e, AuditEvent::PolicyCreated { .. }))
                    .unwrap_or_else(|| panic!("{name}: no PolicyCreated event found"));

                if let AuditEvent::PolicyCreated {
                    preset: p,
                    deny_count,
                    allow_count,
                    ..
                } = created
                {
                    let fields = &expected["fields"];
                    assert_eq!(
                        p,
                        fields["preset"].as_str().unwrap(),
                        "{name}: preset mismatch"
                    );
                    if let Some(min) = fields.get("deny_count_min").and_then(|v| v.as_u64()) {
                        assert!(
                            *deny_count >= min as usize,
                            "{name}: deny_count {deny_count} < min {min}"
                        );
                    }
                    assert_eq!(
                        *allow_count,
                        fields["allow_count"].as_u64().unwrap() as usize,
                        "{name}: allow_count mismatch"
                    );
                }
            }
            // UrlValidated, HostValidated, ConnectionAttempt, and RedirectIntercepted
            // events are not yet emitted by the core engine. These will be testable
            // once P6a (Detection-Grade AuditEvent Fields) lands the emission code.
            "validate_url" | "validate_host" | "connection_attempt" | "redirect_intercepted" => {}
            _ => panic!("{name}: unknown action: {action}"),
        }
    }
}

#[test]
fn redirect_chain_vectors() {
    let path = vectors_dir().join("redirect_chains.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let data: serde_json::Value = serde_json::from_str(&content).unwrap();

    for case in data["test_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let chain: Vec<&str> = case["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let preset = parse_preset(case["policy_preset"].as_str().unwrap());
        let expected = case["expected"].as_str().unwrap();
        let max_redirects = case.get("max_redirects").and_then(|v| v.as_u64());

        let mut builder = PolicyBuilder::new(preset);

        if let Some(allow_arr) = case.get("allow_cidrs").and_then(|v| v.as_array()) {
            let allows: Vec<&str> = allow_arr.iter().map(|v| v.as_str().unwrap()).collect();
            builder.add_allowed(&allows);
        }

        if case
            .get("allow_plaintext_http")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            builder.protocol_rules(ressrf_core::policy::ProtocolRules {
                allow_plaintext_http: true,
                require_https: false,
            });
        }

        let policy = builder.build();
        let validator = UriValidator::new();

        let limit = max_redirects.map(|m| m as usize).unwrap_or(usize::MAX);
        let mut blocked_at: Option<usize> = None;

        // Hop 0 is the origin URL; redirect targets start at hop 1.
        for (i, url) in chain.iter().enumerate().skip(1) {
            if i >= limit {
                blocked_at = Some(i);
                break;
            }

            // Check scheme via protocol rules (plaintext HTTP, require_https).
            let scheme_blocked = url
                .find("://")
                .map(|pos| &url[..pos])
                .is_some_and(|scheme| policy.validate_scheme(scheme).is_err());

            if scheme_blocked || validator.validate_url(url, Some(&policy)).is_err() {
                blocked_at = Some(i);
                break;
            }
        }

        match expected {
            "allowed" => {
                assert!(
                    blocked_at.is_none(),
                    "{name}: expected allowed, but blocked at hop {}",
                    blocked_at.unwrap_or(0)
                );
            }
            "blocked" => {
                let expected_hop = case
                    .get("blocked_at_hop")
                    .and_then(|v| v.as_u64())
                    .map(|h| h as usize);
                assert!(
                    blocked_at.is_some(),
                    "{name}: expected blocked, got allowed"
                );
                if let Some(eh) = expected_hop {
                    assert_eq!(
                        blocked_at.unwrap(),
                        eh,
                        "{name}: expected blocked at hop {eh}, got {}",
                        blocked_at.unwrap()
                    );
                }
            }
            _ => panic!("{name}: unknown expected: {expected}"),
        }
    }
}
