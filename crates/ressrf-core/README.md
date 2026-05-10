# ressrf-core

The foundational SSRF prevention engine. Provides CIDR parsing, IP range management, policy evaluation, URI validation, cloud provider modules, and audit event types. This crate is `no_std`-compatible (with `alloc`) when the `std` feature is disabled, making it suitable for WASM targets.

## Features

- **CIDR engine:** parse v4/v6 notation, IPv4-mapped IPv6 normalization, bitwise containment checks, reject octal/hex/zone-ID tricks
- **Default deny list:** IANA special-purpose registries compiled from `config/ip_ranges.json` via `build.rs`
- **Policy engine:** presets (`ExternalOnly`, `InternalOnly`, `None`), custom allow/deny CIDR lists where allow overrides deny, URL rules (glob + regex), header and protocol rules, immutable after build
- **URL rules:** structured allow/deny rules with scheme, host glob (`*` = single label), path glob (`*`/`**`), optional regex (1MB automaton limit, ReDoS-safe), and per-rule `bypass_ip_check`
- **URI validator:** protocol allowlist, IDN-safe domain matching, userinfo bypass resistance, bare IP detection, cloud domain integration
- **Cloud modules:** AWS (IMDS, ECS, IMDSv2 IPv6), Azure (IMDS, Wireserver, sovereign domains), GCP (metadata, internal DNS). Constants generated from `config/domains_*.json` at build time.
- **Service range trie** (std only): `ServiceRangeTable` backed by `prefix-trie` for O(log n) longest-prefix-match lookups against cloud service IP ranges
- **Audit types:** `AuditEvent` enum with 5 variants, `AuditSink` trait, zero overhead when unused

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | yes | Enables `ServiceRangeTable`, `prefix-trie`, `ipnet`, `regex`, and `std::error::Error` impl |

Without `std`, the crate uses `#![no_std]` with `alloc` for WASM and embedded targets.

## Usage

```rust
use ressrf_core::{PolicyBuilder, Preset, UriValidator};

// Create a policy that blocks internal/metadata ranges
let mut builder = PolicyBuilder::external_only();
builder.add_allowed(&["10.42.0.0/16"]); // permit a known internal service
let policy = builder.build();

// Validate IPs
assert!(policy.is_network_allowed(&["93.184.216.34".parse().unwrap()]).is_ok());
assert!(policy.is_network_allowed(&["169.254.169.254".parse().unwrap()]).is_err());

// Validate URLs
let validator = UriValidator::default();
assert!(validator.validate_url("https://example.com", Some(&policy)).is_ok());
```

## Cloud Providers

```rust
use ressrf_core::PolicyBuilder;

let policy = PolicyBuilder::external_only()
    .with_cloud("aws")
    .with_cloud("azure")
    .with_cloud("gcp")
    .build();
```

## URL Rules

```rust
use ressrf_core::{PolicyBuilder, UrlRule};

let mut builder = PolicyBuilder::external_only();
builder
    .url_allow(UrlRule::glob("https", "*.stripe.com", "/v1/**"))
    .url_allow(UrlRule::host("internal-api.company.com").bypass_ip_check())
    .url_deny(UrlRule::host("*.internal"))
    .url_deny(UrlRule::regex(r"^http://.*$"));
let policy = builder.build();

// Matching allow rule
assert!(policy.validate_url_rules("https://api.stripe.com/v1/charges").is_ok());

// Blocked by deny rule
assert!(policy.validate_url_rules("https://db.internal/query").is_err());
```

## Service Range Lookups

```rust
use ressrf_core::ServiceRangeTable;

let table = ServiceRangeTable::load_all("crates/ressrf-core/config")?;
if let Some(info) = table.lookup("52.94.76.0".parse().unwrap()) {
    println!("{} / {}", info.provider, info.service);
}
```

## License

MIT
