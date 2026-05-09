#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ressrf_core::policy::PolicyBuilder;
use ressrf_core::uri_validator::UriValidator;

#[derive(Debug, Arbitrary)]
struct UrlInput {
    url: String,
    trusted_suffixes: Vec<String>,
    denied_suffixes: Vec<String>,
    with_policy: bool,
}

fuzz_target!(|input: UrlInput| {
    let mut validator = UriValidator::new();

    let trusted_refs: Vec<&str> = input.trusted_suffixes.iter().map(String::as_str).collect();
    validator.add_trusted_suffixes(&trusted_refs);

    let denied_refs: Vec<&str> = input.denied_suffixes.iter().map(String::as_str).collect();
    validator.add_denied_suffixes(&denied_refs);

    let policy = if input.with_policy {
        Some(PolicyBuilder::external_only().build())
    } else {
        None
    };

    // Should never panic, only return Ok/Err
    let _ = validator.validate_url(&input.url, policy.as_ref());
});
