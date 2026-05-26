<p align="center">
    <img src="assets/ressrf-logo.png" alt="ressrf" width="200">
</p>

[![CI](https://github.com/timescale/ressrf/actions/workflows/ci.yml/badge.svg)](https://github.com/timescale/ressrf/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A multi-platform SSRF prevention library with a fuzz-tested Rust core, pluggable protocol transports, pluggable audit logging, and bindings for Go, Python, and Node.js.

ressrf (pronounced "resurf") validates network destinations against configurable deny/allow policies before any connection is made. It blocks access to private networks, cloud metadata endpoints (AWS IMDS, Azure Wireserver, GCP metadata), link-local addresses, and other internal ranges by default. Protocol adapters integrate at DNS resolution and connection establishment, providing transparent protection for HTTP clients, TCP connections, and SSH sessions.

## Key Features

- **Deny-first policy engine** with presets, custom allow/deny CIDR lists, URL rules, and cloud provider modules
- **Default deny list** sourced from IANA special-purpose registries, kept fresh by automated monthly updates
- **Protocol adapters** for HTTP (redirect re-validation), TCP (DNS-pinned dialing), and SSH in every language
- **Pluggable audit logging** via simple callback interface, consistent across all bindings
- **Cross-language conformance** guaranteed by shared JSON test vectors
- **Fuzz-tested** with cargo-fuzz (weekly CI runs)

## Packages

| Package | Language | Integration | Docs |
|---------|----------|-------------|------|
| [`ressrf-core`](crates/ressrf-core/) | Rust | Direct dependency | [README](crates/ressrf-core/README.md) |
| [`ressrf-tcp`](crates/ressrf-tcp/) | Rust | DNS-pinned TCP dialing | [README](crates/ressrf-tcp/README.md) |
| [`ressrf-http`](crates/ressrf-http/) | Rust | Tower Layer/Service | [README](crates/ressrf-http/README.md) |
| [`ressrf-ssh`](crates/ressrf-ssh/) | Rust | Guard for russh/async-ssh2 | [README](crates/ressrf-ssh/README.md) |
| [`ressrf-tracing`](crates/ressrf-tracing/) | Rust | TracingSink audit adapter | [README](crates/ressrf-tracing/README.md) |
| [`ressrf-wasm`](crates/ressrf-wasm/) | Rust | WASM ABI for Go/Node.js | [README](crates/ressrf-wasm/README.md) |
| [`go/ressrf`](go/ressrf/) | Go | wazero WASM runtime | [README](go/ressrf/README.md) |
| [`go-native/ressrf`](go-native/ressrf/) | Go | Native port (no WASM, no CGO) | [README](go-native/ressrf/README.md) |
| [`python/`](python/) | Python | PyO3 native extension | [README](python/README.md) |
| [`node/`](node/) | TypeScript | WebAssembly API | [README](node/README.md) |

```
                     ┌─────────────────────────┐
                     │      ressrf-core        │
                     │  (policy, CIDR, URI,    │
                     │   audit, cloud, trie)   │
                     └───────┬─────────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
   ┌────────────────┐ ┌─────────────┐  ┌────────────────┐
   │  ressrf-wasm   │ │ ressrf-http │  │  ressrf-ssh    │
   │  (WASM ABI)    │ │ (Tower)     │  │  (russh)       │
   └───────┬────────┘ └──────┬──────┘  └───────┬────────┘
           │                 │                 │
     ┌─────┴─────┐           └───────┬─────────┘
     │           │                   │
     ▼           ▼                   ▼
┌─────────┐ ┌──────────┐      ┌──────────────┐
│   Go    │ │  Node.js │      │    Python    │
│ (wazero)│ │  (WASM)  │      │   (PyO3)     │
└─────────┘ └──────────┘      └──────────────┘
```

Go additionally ships a native port at [`go-native/ressrf/`](go-native/ressrf/)
that reimplements the engine in pure Go (`net/netip` + `regexp`). It
consumes the same `tests/vectors/` conformance contract and stays in
lockstep with `ressrf-core` via a differential-fuzz harness that
compares every random URL against the WASM oracle. No WASM runtime,
no embedded `.wasm`, no Rust toolchain in the build pipeline — useful
for Go shops that prefer native debuggability (`pprof`, `delve`) and
contribution flow (no Rust toolchain in PRs).

## Quick Start

### Rust

```rust
use ressrf_core::{PolicyBuilder, UriValidator};

let policy = PolicyBuilder::external_only().build();

assert!(policy.is_network_allowed(&["10.0.0.1".parse().unwrap()]).is_err());
assert!(policy.is_network_allowed(&["93.184.216.34".parse().unwrap()]).is_ok());
```

### Go (wazero, shared Rust engine)

```go
policy, _ := ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
    WithCloudProviders("aws", "azure", "gcp").
    Build(ctx)
defer policy.Close(ctx)

err := policy.IsAllowed(ctx, "http://169.254.169.254/latest/meta-data/")
// err: blocked
```

### Go (native)

```go
policy, _ := ressrf.NewPolicy(ressrf.PresetExternalOnly,
    ressrf.WithCloudProviderDenies(ressrf.CloudAWS, ressrf.CloudAzure, ressrf.CloudGCP),
)

err := policy.IsAllowed(ctx, "http://169.254.169.254/latest/meta-data/")
// err: blocked
```

### Python

```python
from ressrf import Policy, RessrfBlockedError

policy = Policy.external_only(cloud=["aws"])

try:
    policy.validate_url("http://169.254.169.254/latest/meta-data/")
except RessrfBlockedError as e:
    print(f"Blocked: {e.reason}")
```

### Node.js

```typescript
import { Policy, isBlocked } from "ressrf";

const policy = await Policy.externalOnly({ cloud: ["aws"] });

try {
  policy.isAllowed("http://169.254.169.254/latest/meta-data/");
} catch (err) {
  if (isBlocked(err)) console.log("Blocked:", err.reason);
}
```

## Installation

| Language | Command | Requirements |
|----------|---------|--------------|
| Rust | `cargo add ressrf-core` | Rust 1.75+ |
| Go (wazero) | `go get github.com/timescale/ressrf/go/ressrf` | Go 1.26+ |
| Go (native) | `go get github.com/timescale/ressrf/go-native/ressrf` | Go 1.25+ |
| Python | `pip install ressrf` | Python 3.10+ |
| Node.js | `npm install ressrf` | Node.js 20+ |

See each package's README for optional extras (protocol adapters, feature flags).

## Allow Lists

Allow overrides deny. Punch holes for specific CIDRs while keeping the rest of private address space blocked:

```rust
// Rust
PolicyBuilder::external_only().add_allowed(&["10.42.0.0/16"]).build();
```

```go
// Go (wazero)
NewPolicyBuilder(PresetExternalOnly).WithAllowedCIDRs("10.42.0.0/16").Build(ctx)
```

```go
// Go (native)
ressrf.NewPolicy(ressrf.PresetExternalOnly, ressrf.WithAllowedCIDRs("10.42.0.0/16"))
```

```python
# Python
Policy.external_only(allowed=["10.42.0.0/16"])
```

```typescript
// Node.js
await Policy.externalOnly({ allowCidrs: ["10.42.0.0/16"] });
```

## URL Rules

For URL-level allow/deny beyond CIDR-based filtering. Rules use glob patterns for host (`*` = single DNS label) and path (`*` = single segment, `**` = any depth), with optional regex for complex patterns:

```rust
// Rust
PolicyBuilder::external_only()
    .url_allow(UrlRule::glob("https", "*.stripe.com", "/v1/**"))
    .url_deny(UrlRule::host("*.internal"))
    .build();
```

```go
// Go (wazero)
NewPolicyBuilder(PresetExternalOnly).
    WithURLAllow(URLRule{Scheme: "https", Host: "*.stripe.com", Path: "/v1/**"}).
    WithURLDeny(URLRule{Host: "*.internal"}).
    Build(ctx)
```

```go
// Go (native)
ressrf.NewPolicy(ressrf.PresetExternalOnly,
    ressrf.WithURLAllow(ressrf.URLRuleGlob("https", "*.stripe.com", "/v1/**")),
    ressrf.WithURLDeny(ressrf.URLRuleGlob("", "*.internal", "")),
)
```

```python
# Python
PolicyBuilder("external_only") \
    .url_allow(scheme="https", host="*.stripe.com", path="/v1/**") \
    .url_deny(host="*.internal") \
    .build()
```

```typescript
// Node.js
new PolicyBuilder("external_only")
  .urlAllow({ scheme: "https", host: "*.stripe.com", path: "/v1/**" })
  .urlDeny({ host: "*.internal" })
  .build();
```

Deny rules are checked first. When allow rules are configured, URLs not matching any allow rule are blocked. Set `bypass_ip_check: true` on an allow rule to skip the IP-level check for trusted endpoints.

## Audit Logging

All bindings expose the same pluggable interface. The library emits structured events but never dictates which logging framework to use:

```rust
// Rust: implement the AuditSink trait
let policy = PolicyBuilder::external_only()
    .audit_sink(Box::new(my_sink))
    .build();
```

```go
// Go: any function works
sink := ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
    slog.InfoContext(ctx, "ressrf", "kind", e.Kind)
})
```

```python
# Python: any callable works
sink = AuditFunc(lambda event: print(f"[{event.event_type}] {event.fields}"))
```

```typescript
// Node.js: any object with emit() works
const sink = new AuditFunc((event) => console.log(event.kind, event.fields));
```

## IP Ranges Codegen

`scripts/generate_ip_ranges.py` fetches upstream IP range data from IANA, AWS, Azure, and GCP. A monthly CI workflow validates changes and opens a PR automatically. Service ranges are queryable at runtime via `ServiceRangeTable` (trie-backed, O(log n) lookups).

```bash
python scripts/generate_ip_ranges.py              # full update
python scripts/generate_ip_ranges.py --iana-only  # skip cloud service ranges
python scripts/generate_ip_ranges.py --validate-only
```

## Testing

Shared test vectors in `tests/vectors/` ensure identical behavior across all languages, including a 92-case `ssrf_techniques.json` covering the full SSRF bypass technique taxonomy (IP representation tricks, IPv6 variants, parser confusion, protocol smuggling, cloud metadata, Unicode/IDN, and more):

```bash
cargo test --workspace --all-features          # Rust
cd go/ressrf && go test -race ./...            # Go (wazero)
cd go-native/ressrf && go test -race ./...     # Go (native)
cd python && uv run pytest tests/ -v           # Python
cd node && npx tsx --test tests/*.test.ts      # Node.js
```

A Tier 2 end-to-end suite under `crates/ressrf-tcp/tests/ssrf_e2e.rs` exercises DNS-rebinding pinning and redirect chains through the full network stack using CoreDNS and WireMock containers (`tests/containers/`). It is gated behind the `e2e` Cargo feature and requires Docker; tests skip with a notice when Docker is unavailable:

```bash
cargo test --features e2e -p ressrf-tcp --test ssrf_e2e
```

## CI/CD

- **Rust:** check, fmt, clippy, test (Linux/macOS/Windows), WASM build
- **Go (wazero + native):** test (multi-OS, race detector), vet, golangci-lint; the native port additionally runs a differential-fuzz job against the wazero binding's WASM oracle
- **Python:** pytest (multi-OS), ruff, ty
- **Node.js:** node:test (multi-OS), tsc
- **SSRF e2e:** Linux-only Tier 2 job spins up CoreDNS + WireMock to verify DNS-based and redirect-based bypasses end-to-end
- **Security:** cargo audit, govulncheck, cargo-fuzz (weekly), zizmor
- **IP ranges:** monthly upstream fetch, validate, test, auto-PR

## Contributing

If you would like to see integration with your favorite programming language, cloud provider, protocol, or library, feel free to open an issue or submit a pull request. Contributions of all kinds are welcome.

See [HACKING.md](HACKING.md) for development setup, testing, and step-by-step guides for adding new cloud providers, language bindings, protocol adapters, and client library integrations.

## License

MIT
