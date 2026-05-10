//! Integration tests driven by shared JSON test vectors.

use std::net::IpAddr;
use std::path::PathBuf;

use ressrf_core::cidr::Cidr;
use ressrf_core::error::DataTier;
use ressrf_core::policy::{PolicyBuilder, Preset};
use ressrf_core::uri_validator::UriValidator;
use ressrf_core::url_rules::UrlRuleset;

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
