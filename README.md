# ressrf

[![CI](https://github.com/mostafa/ressrf/actions/workflows/ci.yml/badge.svg)](https://github.com/mostafa/ressrf/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A multi-platform SSRF prevention library with a fuzz-tested Rust core, pluggable protocol transports, pluggable audit logging, and bindings for Go, Python, and Node.js. The Rust core compiles to WASM for Go and Node.js, and uses PyO3 for Python, sharing the same policy engine and test vectors across all languages.

ressrf, pronounced resurf, validates network destinations (IPs, URLs, DNS results) against configurable deny/allow policies before any connection is made. It blocks access to private networks, cloud metadata endpoints (AWS IMDS, Azure Wireserver, GCP metadata), link-local addresses, and other internal ranges by default. Protocol adapters integrate at the DNS resolution and connection establishment level, providing transparent SSRF protection for HTTP clients, TCP connections, and SSH sessions.

## Supported Features

- **Policy engine:** presets (ExternalOnly, InternalOnly, None), custom allow/deny CIDR lists, IPv4 and IPv6 support, IPv4-mapped IPv6 normalization
- **Default deny list:** IANA special-purpose registries, RFC1918, CGNAT, loopback, link-local, multicast, cloud IMDS (AWS, Azure, GCP), 6to4, Teredo, NAT64, documentation ranges
- **IP ranges codegen:** automated script fetches IANA registries plus AWS, Azure, and GCP service IP ranges; trie-backed `ServiceRangeTable` for O(log n) longest-prefix-match lookups; monthly CI workflow keeps data fresh
- **URI validation:** protocol allowlist (HTTP, HTTPS, WS, WSS), IDN-safe domain matching, userinfo bypass resistance, bare IP detection
- **Pluggable audit logging:** structured events via callback interface (no opinion on logging framework), consistent across all languages
- **Protocol adapters per language:**
  - HTTP: DNS interception, redirect re-validation per hop
  - TCP: policy-validated connections at the socket level
  - SSH: connect over pre-validated TCP sockets
- **Cross-language conformance:** shared JSON test vectors ensuring identical behavior across Rust, Go, Python, and Node.js
- **Fuzz targets:** `cargo-fuzz` with libfuzzer for CIDR parsing, policy decisions, and URL validation

## Architecture

| Component | Language | Description |
|-----------|----------|-------------|
| [`crates/ressrf-core`](crates/ressrf-core/) | Rust | Core policy engine, CIDR matching, URI validation, audit types, service range trie |
| [`crates/ressrf-http`](crates/ressrf-http/) | Rust | Tower Layer/Service with DNS validation and redirect interception |
| [`crates/ressrf-ssh`](crates/ressrf-ssh/) | Rust | Guard wrapper for russh/async-ssh2 |
| [`crates/ressrf-wasm`](crates/ressrf-wasm/) | Rust | WASM ABI wrapper (wasm32-wasip1) for Go and Node.js |
| [`go/ressrf`](go/ressrf/) | Go | wazero-powered WASM integration with http.Agent, net.Dialer, SSH |
| [`python/`](python/) | Python | PyO3 native extension with httpx, requests, paramiko adapters |
| [`node/`](node/) | TypeScript | WebAssembly-based with undici, node:http, ssh2 adapters |
| [`scripts/`](scripts/) | Python | IP ranges codegen (IANA + AWS/Azure/GCP service ranges) |

```
                     ┌─────────────────────────┐
                     │      ressrf-core        │
                     │  (Rust: policy, CIDR,   │
                     │   URI, audit)           │
                     └────────┬────────────────┘
                              │
            ┌─────────────────┼──────────────────┐
            │                 │                  │
            ▼                 ▼                  ▼
   ┌────────────────┐ ┌─────────────┐  ┌────────────────┐
   │  ressrf-wasm   │ │ ressrf-http │  │  ressrf-ssh    │
   │  (WASM ABI)    │ │ (Tower)     │  │  (russh)       │
   └───────┬────────┘ └─────────────┘  └────────────────┘
           │
     ┌─────┴─────┐
     │           │
     ▼           ▼
┌─────────┐ ┌──────────┐      ┌──────────────┐
│   Go    │ │  Node.js │      │    Python    │
│ (wazero)│ │  (WASM)  │      │   (PyO3)     │
└─────────┘ └──────────┘      └──────────────┘
```

## Quick Start

### Go

```go
package main

import (
    "context"
    "fmt"
    "net/http"

    "github.com/mostafa/ressrf/go/ressrf"
)

func main() {
    ctx := context.Background()

    policy, err := ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
        WithAuditSink(ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
            fmt.Printf("audit: %s\n", e.Kind)
        })).
        Build(ctx)
    if err != nil {
        panic(err)
    }
    defer policy.Close(ctx)

    // Check a URL
    if err := policy.IsAllowed(ctx, "http://169.254.169.254/latest/meta-data/"); err != nil {
        fmt.Println("Blocked:", err) // IMDS blocked
    }

    // Check IPs directly
    if err := policy.IsNetworkAllowed(ctx, []string{"10.0.0.1"}); err != nil {
        fmt.Println("Blocked:", err) // Private IP blocked
    }
}
```

### Python

```python
from ressrf import Policy, PolicyBuilder, RessrfBlockedError
from ressrf.protocols.http import SafeTransport

# Quick setup with a preset
policy = Policy.external_only()

# Validate a URL
try:
    policy.validate_url("http://169.254.169.254/latest/meta-data/")
except RessrfBlockedError as e:
    print(f"Blocked: {e.reason}")

# Use with httpx
import httpx
transport = SafeTransport(policy)
client = httpx.Client(transport=transport)
response = client.get("https://api.example.com/data")  # safe
```

### Node.js (TypeScript)

```typescript
import { Policy, isBlocked } from "ressrf";
import { httpAgent } from "ressrf/protocols/http";

const policy = await Policy.externalOnly();

// Check a URL
try {
  policy.isAllowed("http://169.254.169.254/latest/meta-data/");
} catch (err) {
  if (isBlocked(err)) {
    console.log("Blocked:", err.reason);
  }
}

// Use with node:http
import http from "node:http";
const agent = httpAgent(policy);
http.get("https://api.example.com/data", { agent }, (res) => {
  // DNS resolution validated against policy
});
```

### Rust

```rust
use ressrf_core::{PolicyBuilder, Preset, UriValidator};

let policy = PolicyBuilder::new(Preset::ExternalOnly).build();

// Check IPs
let ips = ["10.0.0.1".parse().unwrap()];
assert!(policy.is_network_allowed(&ips).is_err()); // private IP blocked

// Validate a URL
let validator = UriValidator::default();
assert!(validator.validate_url("http://169.254.169.254/", Some(&policy)).is_err());
```

## Installation

### Go

```bash
go get github.com/mostafa/ressrf/go/ressrf
```

Requires Go 1.22+. The WASM binary is embedded via `//go:embed` so there are no external files to manage.

### Python

```bash
pip install ressrf

# With optional protocol adapters
pip install ressrf[httpx]       # httpx SafeTransport
pip install ressrf[requests]    # requests SafeAdapter
pip install ressrf[ssh]         # paramiko safe_ssh_connect
pip install ressrf[all]         # all adapters
```

Requires Python 3.10+. The package ships a native extension built with PyO3/maturin.

### Node.js

```bash
npm install ressrf
```

Requires Node.js 20+. The package bundles `core.wasm` and has zero runtime dependencies. Protocol adapters for `undici` and `ssh2` are optional peer dependencies.

### Rust

```toml
[dependencies]
ressrf-core = "0.1"
ressrf-http = "0.1"  # optional: Tower HTTP layer
ressrf-ssh = "0.1"   # optional: SSH guard
```

## Audit Logging

All language bindings expose the same pluggable audit interface. The library emits structured events but never dictates which logging framework to use.

```rust
// Rust: implement the AuditSink trait
use ressrf_core::audit::{AuditSink, AuditEvent};

struct MySink;
impl AuditSink for MySink {
    fn emit(&self, event: &AuditEvent) {
        println!("audit: {event:?}");
    }
}

let policy = PolicyBuilder::new(Preset::ExternalOnly)
    .audit_sink(Box::new(MySink))
    .build();
```

```go
// Go: any function works
sink := ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
    slog.InfoContext(ctx, "ressrf.audit", "kind", e.Kind)
})
```

```python
# Python: any callable works
from ressrf import AuditFunc
sink = AuditFunc(lambda event: print(f"[{event.kind}] {event.fields}"))
```

```typescript
// Node.js: any object with emit() works
import { AuditFunc } from "ressrf";
const sink = new AuditFunc((event) => console.log(event.kind, event.fields));
```

## Testing

Shared test vectors in `tests/vectors/` ensure cross-language conformance:

- `cidr_containment.json` - CIDR range membership
- `policy_decisions.json` - Policy engine with presets and overrides
- `url_validation.json` - URL scheme, domain, and bypass resistance
- `audit_events.json` - Audit event structure
- `redirect_chains.json` - Multi-hop redirect validation

```bash
# Rust
cargo test --workspace --all-features

# Go
cd go/ressrf && go test -race ./...

# Python
cd python && uv run pytest tests/ -v

# Node.js
cd node && npx tsx --test tests/*.test.ts
```

## Building from Source

```bash
# Build the Rust workspace
cargo build --release

# Build WASM (required for Go and Node.js)
bash go/ressrf/build_wasm.sh

# Build Python extension
cd python && uv run maturin develop

# Install Node.js deps
cd node && npm install
```

The WASM build requires `wasm32-wasip1` target, `wasm-opt` (from Binaryen), and `wasm-tools`:

```bash
rustup target add wasm32-wasip1
cargo install wasm-tools
```

## IP Ranges Codegen

The deny list and cloud service ranges are kept up to date by `scripts/generate_ip_ranges.py`, a stdlib-only Python script that fetches upstream data:

- **IANA:** IPv4/IPv6 special-purpose registry CSVs (non-globally-reachable ranges)
- **AWS:** `ip-ranges.json` grouped by service (EC2, S3, CLOUDFRONT, etc.)
- **Azure:** ServiceTags JSON (handles weekly rotating download URL)
- **GCP:** `cloud.json` + `goog.json`

Outputs land in `crates/ressrf-core/config/` and are compiled into Rust constants via `build.rs`. Service IP ranges are loaded at runtime into a `ServiceRangeTable` (backed by `prefix-trie`) for efficient lookups:

```rust
use ressrf_core::ServiceRangeTable;

let table = ServiceRangeTable::load_all("crates/ressrf-core/config")?;
if let Some(info) = table.lookup("52.94.76.0".parse().unwrap()) {
    println!("IP belongs to {} / {}", info.provider, info.service);
}
```

A monthly GitHub Actions workflow (`.github/workflows/update-ip-ranges.yml`) runs the script, validates the output, runs the full test suite, and opens a PR if anything changed.

```bash
# Run manually
python scripts/generate_ip_ranges.py

# Validate only (no writes)
python scripts/generate_ip_ranges.py --validate-only

# IANA ranges only (skip cloud service ranges)
python scripts/generate_ip_ranges.py --iana-only
```

## CI/CD

The project runs comprehensive CI on every push and PR:

- **Rust:** check, fmt, clippy, test (multi-OS), build-wasm
- **Go:** test (multi-OS, race detector), vet, golangci-lint
- **Python:** pytest (multi-OS), ruff format/lint, ty type check
- **Node.js:** node:test (multi-OS), tsc type check
- **Security:** cargo audit, cargo fuzz (weekly), zizmor (Actions linting)
- **IP ranges:** monthly cron fetches upstream IANA and cloud service ranges, validates, tests, and opens a PR

## Contributing

If you would like to see integration with your favorite programming language, cloud provider, protocol, or library, feel free to open an issue or submit a pull request. Contributions of all kinds are welcome.

## License

MIT
