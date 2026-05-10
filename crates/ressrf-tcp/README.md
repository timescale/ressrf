# ressrf-tcp

Async TCP guard with DNS-pinned dialing for SSRF prevention. Resolves hostnames, validates all resulting IPs against a `ressrf-core` policy, and only establishes connections to allowed addresses.

## Features

- **SafeResolver:** resolves DNS and validates every IP before returning results
- **SafeConnector:** `tokio::net::TcpStream` connector that dials only policy-approved addresses
- **DNS backends:** built-in Tokio DNS (`TokioDns`) and optional hickory-resolver (`HickoryDns`) for DNS-over-TLS/HTTPS
- **DNS pinning:** resolved IPs are checked at resolution time, preventing TOCTOU races between resolve and connect

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `hickory` | no | Enables `HickoryDns` backend via `hickory-resolver` |

## Public API

| Type | Description |
|------|-------------|
| `SafeResolver` | Resolves and validates DNS results against policy |
| `SafeConnector` | Connects TCP streams to policy-validated addresses |
| `DnsBackend` | Trait for pluggable DNS resolution |
| `TokioDns` | Default DNS backend using `tokio::net` |
| `HickoryDns` | Optional backend via hickory-resolver |
| `TcpGuardError` | Error type for resolution/connection failures |
| `ResolveResult` | Validated resolution output |

## Usage

```rust
use ressrf_core::PolicyBuilder;
use ressrf_tcp::{SafeConnector, TokioDns};

let policy = PolicyBuilder::external_only().build();
let connector = SafeConnector::new(policy, TokioDns);

// Connects only if DNS results pass the policy
let stream = connector.connect("example.com", 443).await?;
```

## License

MIT
