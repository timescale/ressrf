//! Integration test runner for `tests/vectors/redirect_chains.json`.
//!
//! Walks each redirect chain through `RedirectValidator::validate_hop`
//! plus `Policy::validate_scheme` on every hop after the origin. Per
//! the BS-7 design note in `RedirectValidator`, hostname-based redirect
//! targets are only IP-checked at the TCP layer; this runner therefore
//! exercises the URL-level decisions that the validator can make
//! without DNS:
//!
//! - `bare_ip_in_deny_range`: the redirect target is a bare IP literal
//!   in the policy's deny set
//! - `scheme_not_allowed`: the redirect target uses a forbidden scheme
//! - `plaintext_http_denied`: the redirect target downgrades to `http`
//!   when the policy requires `https`
//! - `max_redirects_exceeded`: too many hops follow
//!
//! The redirect chain JSON is also consumed by the Tier 2 `WireMock`
//! e2e suite (`crates/ressrf-tcp/tests/ssrf_e2e.rs`) for full
//! end-to-end verification with real HTTP responses.

use std::path::PathBuf;
use std::sync::Arc;

use ressrf_core::policy::{PolicyBuilder, Preset, ProtocolRules};
use ressrf_http::{HttpGuardError, RedirectPolicy, RedirectValidator};

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("vectors")
        .join("redirect_chains.json")
}

#[derive(Debug)]
struct Outcome {
    blocked_at_hop: Option<u32>,
    too_many_redirects: bool,
}

fn walk_chain(chain: &[String], validator: &RedirectValidator) -> Outcome {
    // The first URL in `chain` is the originating request; subsequent
    // entries are redirect targets that arrive in `Location` headers.
    // `RedirectValidator::validate_hop` is therefore called once per
    // entry from index 1 onward.
    for (idx, hop_url) in chain.iter().enumerate().skip(1) {
        match validator.validate_hop(hop_url) {
            Ok(()) => {}
            Err(HttpGuardError::TooManyRedirects { .. }) => {
                return Outcome {
                    blocked_at_hop: Some(u32::try_from(idx).unwrap()),
                    too_many_redirects: true,
                };
            }
            Err(_) => {
                return Outcome {
                    blocked_at_hop: Some(u32::try_from(idx).unwrap()),
                    too_many_redirects: false,
                };
            }
        }
    }
    Outcome {
        blocked_at_hop: None,
        too_many_redirects: false,
    }
}

#[test]
fn redirect_chain_vectors() {
    let path = vectors_path();
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
    let data: serde_json::Value =
        serde_json::from_str(&content).expect("redirect_chains.json invalid");

    let cases = data["test_cases"]
        .as_array()
        .expect("redirect_chains.json missing `test_cases` array");

    let mut failures: Vec<String> = Vec::new();

    for case in cases {
        let name = case["name"].as_str().expect("case missing `name`");
        let chain: Vec<String> = case["chain"]
            .as_array()
            .expect("case missing `chain`")
            .iter()
            .map(|v| v.as_str().expect("chain entry not a string").to_string())
            .collect();
        let preset_str = case["policy_preset"].as_str().unwrap_or("external_only");
        let expected = case["expected"].as_str().expect("case missing `expected`");
        let expected_hop = case
            .get("blocked_at_hop")
            .and_then(serde_json::Value::as_u64);

        let preset = match preset_str {
            "external_only" => Preset::ExternalOnly,
            "internal_only" => Preset::InternalOnly,
            "none" => Preset::None,
            other => panic!("unknown preset `{other}` in case `{name}`"),
        };

        let mut builder = PolicyBuilder::new(preset);
        if let Some(allow_arr) = case.get("allow_cidrs").and_then(|v| v.as_array()) {
            let allows: Vec<&str> = allow_arr.iter().map(|v| v.as_str().unwrap()).collect();
            builder.add_allowed(&allows);
        }
        if case
            .get("allow_plaintext_http")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            builder.protocol_rules(ProtocolRules {
                allow_plaintext_http: true,
                require_https: false,
            });
        }
        let policy = Arc::new(builder.build());

        // Vector convention: `max_redirects` counts the total number of
        // URLs in the chain including the origin. `RedirectValidator`
        // counts only redirect targets (origin not validated). Subtract 1
        // so a chain of N URLs with vector max_redirects = N is exactly
        // at the limit, and a chain of N+1 URLs trips `TooManyRedirects`
        // on the last hop.
        let vector_max = case
            .get("max_redirects")
            .and_then(serde_json::Value::as_u64)
            .map_or(11, |n| {
                u32::try_from(n).expect("max_redirects out of range")
            });
        let validator_max = vector_max.saturating_sub(1);

        let validator =
            RedirectValidator::new(Arc::clone(&policy), RedirectPolicy::follow(validator_max));

        let outcome = walk_chain(&chain, &validator);

        match expected {
            "allowed" => {
                if let Some(hop) = outcome.blocked_at_hop {
                    failures.push(format!(
                        "{name}: expected allowed, got blocked at hop {hop} \
                         (chain: {chain:?})"
                    ));
                }
            }
            "blocked" => match outcome.blocked_at_hop {
                None => {
                    failures.push(format!(
                        "{name}: expected blocked, got allowed (chain: {chain:?})"
                    ));
                }
                Some(got_hop) => {
                    if let Some(want_hop) = expected_hop {
                        let want_hop_u32 =
                            u32::try_from(want_hop).expect("blocked_at_hop overflow");
                        if got_hop != want_hop_u32 {
                            failures.push(format!(
                                "{name}: expected blocked at hop {want_hop_u32}, got {got_hop} \
                                 (chain: {chain:?})"
                            ));
                        }
                    }
                }
            },
            other => panic!("{name}: unknown `expected` value `{other}`"),
        }

        // Sanity: the `too_many_redirects` flag should match the
        // `reason: max_redirects_exceeded` annotation in the vector.
        if let Some(reason) = case.get("reason").and_then(|v| v.as_str()) {
            if reason == "max_redirects_exceeded" && !outcome.too_many_redirects {
                failures.push(format!(
                    "{name}: vector annotated max_redirects_exceeded, \
                     but validator did not surface TooManyRedirects"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} redirect_chains cases failed:\n  - {}",
        failures.len(),
        cases.len(),
        failures.join("\n  - ")
    );
}
