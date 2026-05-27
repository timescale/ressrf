# Changelog

All notable changes to ressrf are documented in this file.
Each entry corresponds to a [GitHub Release](https://github.com/timescale/ressrf/releases).

## [0.1.0] - TBD

**TL;DR** ressrf v0.1.0 is the first public multi-platform release of the library, shipping SSRF prevention across Rust, Go, Python, and Node.js:

- A fuzz-tested Rust core with deny-first policy engine, CIDR validation, IPv4-mapped-IPv6 normalization, and IANA-sourced default deny lists
- Cloud provider modules for AWS (IMDS, ECS), Azure (IMDS, Wireserver, sovereign domains), and GCP (metadata, internal DNS)
- URL rules with host/path glob matching and ReDoS-safe regex, on top of IDN-safe URI validation with userinfo bypass resistance
- Protocol adapters for HTTP (redirect re-validation), TCP (DNS-pinned dialing), and SSH in all four languages
- Two co-existing Go bindings: a `wazero`-backed binding at `go/ressrf/` that runs the Rust core in WASM, and a native Go port at `go-native/ressrf/` with split `httpx`/`tcpx`/`sshx` subpackages and a typed sealed-sum `DenyReason`. Both share the same JSON conformance vectors and are pinned to the Rust core via a differential-fuzz harness.
- Pluggable audit logging with zero opinion on which logger to use, consistent across Rust, Go, Python, and Node.js
- Automated IP ranges codegen from IANA, AWS, Azure, and GCP upstream sources, with a monthly CI refresh workflow
- Cross-language conformance guaranteed by shared JSON test vectors, including a 92-case SSRF bypass taxonomy, plus multi-OS CI, Docker e2e tests, and a weekly diffuzz job
- Published to crates.io, PyPI, npm, and two Go module tags (`go/ressrf/v0.1.0` and `go-native/ressrf/v0.1.0`)

### Deny-first policy engine

The core policy engine validates IP addresses and hostnames against configurable deny/allow CIDR lists with deny-first semantics. Three built-in presets cover common deployment patterns:

| Preset | Behavior |
|--------|----------|
| `ExternalOnly` | Deny private/internal ranges, allow public internet (most common) |
| `InternalOnly` | Allow only private/internal ranges |
| `None` | No default ranges, fully custom via add_allowed/add_denied |

The default deny list ships in `crates/ressrf-core/config/ip_ranges.json`, sourced from IANA IPv4 and IPv6 special-purpose registries with hand-curated metadata and cloud-provider additions. It covers private use (RFC 1918), loopback, link-local, CGNAT (100.64.0.0/10), TEST-NETs, benchmarking, reserved/broadcast, IPv6 documentation, Teredo, 6to4, NAT64, and multicast ranges.

The CIDR engine handles IPv4-mapped-IPv6 normalization (adjusting the prefix by +96), rejects octal/hex IP representations and zone IDs, and supports edge cases including /0 and /128 prefixes. All unspecified addresses (0.0.0.0, ::) are denied by default. Protocol rules require HTTPS by default and deny plaintext HTTP unless a caller explicitly opts in; header rules can require or reject named headers before a request proceeds.

Allow overrides deny. Punch holes for specific CIDRs while keeping the rest of private address space blocked:

```rust
// Rust
let mut builder = PolicyBuilder::external_only();
builder.add_allowed(&["10.42.0.0/16"]);
let policy = builder.build();
```

```go
// Go (wazero binding, github.com/timescale/ressrf/go/ressrf)
policy, _ := ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
    WithAllowedCIDRs("10.42.0.0/16").
    Build(ctx)
defer policy.Close(ctx)
```

```go
// Go (native port, github.com/timescale/ressrf/go-native/ressrf)
policy, _ := ressrf.NewPolicy(
    ressrf.PresetExternalOnly,
    ressrf.WithAllowedCIDRs("10.42.0.0/16"),
)
```

```python
# Python
policy = Policy.external_only(allowed=["10.42.0.0/16"])
```

```typescript
// Node.js
const policy = await Policy.externalOnly({ allowCidrs: ["10.42.0.0/16"] });
```

### Cloud provider modules

Three cloud providers are supported out of the box. Each module contributes deny ranges for cloud metadata endpoints and domain suffix lists for internal services.

| Provider | Deny ranges | Domain suffixes |
|----------|-------------|-----------------|
| AWS | 169.254.169.254/32 (IMDS), 169.254.170.2/32 (ECS task metadata), fd00:ec2::254/128 (IMDSv2 IPv6) | `*.internal` VPC DNS, `amazonaws.com` internal endpoints |
| Azure | 169.254.169.254/32 (IMDS), 168.63.129.16/32 (Wireserver/DHCP) | `vault.azure.net`, `*.core.windows.net`, `*.database.windows.net`, `*.azurecr.io`, sovereign variants (.cn/.de/.us) |
| GCP | 169.254.169.254/32 (metadata) | `metadata.google.internal`, `*.internal` VPC DNS |

Enable cloud modules by name when building a policy:

```rust
// Rust
use ressrf_core::cloud::CloudProvider;

let mut builder = PolicyBuilder::external_only();
builder
    .with_cloud(CloudProvider::Aws)
    .with_cloud(CloudProvider::Azure)
    .with_cloud(CloudProvider::Gcp);
let policy = builder.build();
```

```go
// Go
ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
    WithCloudProviders("aws", "azure", "gcp").
    Build(ctx)
```

```python
# Python
Policy.external_only(cloud=["aws", "azure", "gcp"])
```

```typescript
// Node.js
await Policy.externalOnly({ cloud: ["aws", "azure", "gcp"] });
```

Cloud deny ranges and domain lists are extracted into JSON config files (`crates/ressrf-core/config/domains_{aws,azure,gcp}.json`) and compiled into Rust constants at build time via `build.rs`.

### URI validation and URL rules

The URI validator provides protocol allowlisting (http/https/ws/wss by default), IDN-safe domain matching via `domainToASCII` with boundary-aware suffix checks, bare IP literal detection, and resistance to userinfo `@` bypass attacks (URL-encoded `%40`). Hostnames containing `--` are rejected to support cloud domain validators.

URL rules add URL-level allow/deny on top of CIDR-based filtering. Rules use glob patterns for host (`*` matches a single DNS label) and path (`*` matches a single segment, `**` matches any depth), with optional full-URL regex (1 MB automaton limit, ReDoS-safe via the `regex` crate).

```rust
// Rust
let mut builder = PolicyBuilder::external_only();
builder
    .url_allow(UrlRule::glob("https", "*.stripe.com", "/v1/**"))
    .url_deny(UrlRule::host("*.internal"));
let policy = builder.build();
```

```go
// Go
ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
    WithURLAllow(ressrf.URLRule{Scheme: "https", Host: "*.stripe.com", Path: "/v1/**"}).
    WithURLDeny(ressrf.URLRule{Host: "*.internal"}).
    Build(ctx)
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

Deny rules are checked first. When allow rules are configured, URLs not matching any allow rule are blocked. Set `bypass_ip_check: true` on an allow rule to skip IP-level validation for trusted endpoints.

### Protocol adapters

Protocol adapters integrate at DNS resolution and connection establishment, providing transparent SSRF protection for HTTP, TCP, and SSH in all four languages. Every adapter validates resolved IP addresses against the policy before allowing the connection to proceed.

| Protocol | Rust | Go | Python | Node.js |
|----------|------|----|--------|---------|
| HTTP | Tower Layer/Service with redirect re-validation per hop; DNS pinning comes from `ressrf-tcp::SafeConnector` | `policy.HTTPTransport(base)` returning `http.RoundTripper`, redirect re-validation at CheckRedirect + Control hook | httpx `SafeTransport`/`AsyncSafeTransport`, requests `SafeAdapter` | `httpAgent`/`httpsAgent` with DNS validation, `safeFetch` with redirect re-validation, `undiciConnect` for undici |
| TCP | `policy.tcp_connect(addr)` async | `SafeDialer` with `net.Dialer.Control` hook, 30s default timeout | `safe_getaddrinfo`, `create_connection` | `createConnection` returning policy-validated `net.Socket`, `dnsLookup` override |
| SSH | Guard wrapper for russh/async-ssh2 | `policy.SSHDial(ctx, addr, sshConfig)` wrapping `ssh.NewClientConn` | `safe_ssh_connect` via paramiko | `safeSshConnect` via ssh2 `sock` option |

HTTP adapters are the most involved because they must re-validate on every redirect hop. In Rust, `ressrf-http` handles Tower integration and redirect validation, while `ressrf-tcp::SafeConnector` provides resolve-once-pin DNS enforcement. Go achieves the same at two layers: `CheckRedirect` validates the new URL and the `Control` hook validates the resolved IP. Python and Node.js intercept `getaddrinfo` and `dns.lookup` respectively to validate before connect.

### Pluggable audit logging

All bindings expose the same pluggable audit interface. The core audit model defines structured `AuditEvent` values (`HostValidated`, `UrlValidated`, `ConnectionAttempt`, `RedirectIntercepted`, `PolicyCreated`) with optional detection fields: `raw_input`, `match_reason`, `caller_context`, and `policy_version`. The library never dictates which logging framework to use. When no sink is configured, the overhead is zero.

| Component | Rust | Go | Python | Node.js |
|-----------|------|----|--------|---------|
| Interface | `AuditSink` trait | `AuditSink` interface | `AuditSink` Protocol (PEP 544) | `AuditSink` TypeScript interface |
| Callback adapter | -- | `AuditFunc` | `AuditFunc` | `AuditFunc` |
| Fan-out | -- | `MultiSink` | `MultiSink` | `MultiSink` |
| No-op | -- | `DiscardSink` | `DiscardSink` | `DiscardSink` |

```rust
// Rust: implement the AuditSink trait
let mut builder = PolicyBuilder::external_only();
builder.audit_sink(Box::new(my_sink));
let policy = builder.build();
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

The `ressrf-tracing` crate provides a ready-made `TracingSink` for Rust that emits `tracing::event!` at configurable levels with structured `ressrf.*` fields, wiring directly into existing `tracing_subscriber` pipelines.

### IP ranges codegen

`scripts/generate_ip_ranges.py` is a stdlib-only Python script that fetches upstream IP range data from four sources:

| Source | Data |
|--------|------|
| IANA IPv4/IPv6 special-purpose registry CSVs | Base deny list (private, loopback, link-local, CGNAT, etc.) |
| AWS `ip-ranges.json` | AWS service CIDRs |
| Azure ServiceTags JSON (rotating URL discovery) | Azure service CIDRs |
| GCP `cloud.json` / `goog.json` | GCP service and Google-owned CIDRs |

The script supports `--iana-only` (skip cloud service ranges), `--validate-only` (check without writing), and `--dry-run`. It includes SHA-256 audit logging, CIDR validation, duplicate detection, and a `csp_metadata` cross-check against provider deny_ranges.

```bash
python scripts/generate_ip_ranges.py              # full update
python scripts/generate_ip_ranges.py --iana-only   # skip cloud service ranges
python scripts/generate_ip_ranges.py --validate-only
```

A `ServiceRangeTable` provides trie-backed O(log n) longest-prefix-match lookups via the `prefix-trie` crate (gated behind the `std` feature). It supports `load_from_file()`, `load_all()`, `lookup()`, `is_service_ip()`, and `merge()`, and integrates with `PolicyBuilder` via optional `with_service_ranges()`.

A monthly CI workflow (`.github/workflows/update-ip-ranges.yml`, 1st of each month) fetches upstream data, runs `--validate-only` and `cargo test`, and opens a PR automatically on changes.

### Cross-language conformance and CI

All four language implementations load the same shared JSON test vectors from `tests/vectors/`:

| Vector file | Coverage |
|-------------|----------|
| `cidr_containment.json` | CIDR parsing and containment checks |
| `ipv4_ipv6_mapping.json` | IPv4-mapped-IPv6 normalization |
| `policy_decisions.json` | Policy preset behavior, cloud providers, allow/deny |
| `url_validation.json` | URI validator edge cases |
| `redirect_chains.json` | Multi-hop redirect re-validation |
| `audit_events.json` | Audit event structure |
| `url_rules.json` | URL rule glob/regex matching, deny precedence, bypass_ip_check |
| `ssrf_techniques.json` | 92-case SSRF bypass taxonomy covering IP representation tricks, IPv6 variants, parser confusion, protocol smuggling, cloud metadata, Unicode/IDN, and more |

Any behavioral divergence between languages causes an independent test failure. The CI matrix runs on Linux, macOS, and Windows for all languages.

Additional quality gates:

| Gate | Tool |
|------|------|
| Rust format + lint | `cargo fmt --check` + `cargo clippy -D warnings` |
| Rust tests | `cargo test --workspace --all-features` (multi-OS) |
| WASM build | `cargo build --target wasm32-wasip1` + `wasm-opt` |
| Go tests | `go test -race ./...` (multi-OS) + `go vet` + `golangci-lint` |
| Python tests | `pytest` (multi-OS) + `ruff` (format + lint) + `ty` (type check) |
| Node.js tests | `node:test` (multi-OS) + `tsc --noEmit` |
| SSRF e2e | Linux-only Docker suite with CoreDNS + WireMock for DNS-rebinding and redirect-chain bypasses |
| Dependency audit | `cargo audit` + `govulncheck` (daily schedule) |
| Fuzz testing | `cargo-fuzz` with 3 targets: `fuzz_cidr`, `fuzz_policy`, `fuzz_url_validator` (weekly) |
| Workflow security | `zizmor --pedantic` on all GitHub Actions workflows |

The Tier 2 e2e suite lives under `crates/ressrf-tcp/tests/ssrf_e2e.rs` and uses shared container assets in `tests/containers/`. It is gated behind the `e2e` Cargo feature and requires Docker:

```bash
cargo test --features e2e -p ressrf-tcp --test ssrf_e2e
```

### Rust crates

| Crate | Description |
|-------|-------------|
| `ressrf-core` | Policy engine, CIDR validation, URI validator, cloud modules, audit types, URL rules, IP range trie |
| `ressrf-tcp` | DNS-pinned async TCP dialing with policy validation at resolve time |
| `ressrf-http` | Tower Layer/Service with redirect re-validation per hop |
| `ressrf-ssh` | Guard wrapper for russh/async-ssh2 with pre-validated SocketAddr |
| `ressrf-tracing` | TracingSink audit adapter emitting `tracing::event!` with structured `ressrf.*` fields |
| `ressrf-wasm` | Thin WASM ABI wrapper exporting policy/validation functions for Go and Node.js consumption |

The first five crates are published to crates.io. `ressrf-wasm` is `publish = false`; it produces the `.wasm` binary embedded by the wazero Go binding and the Node.js binding, and acts as the differential-fuzz oracle for the native Go port.

### Two Go bindings

This release ships two Go modules in the same repo, under one release cadence and the same `tests/vectors/` contract. Both live in-tree; neither is deprecated.

| Path | Runtime | Engine | Picking criteria |
|------|---------|--------|------------------|
| `github.com/timescale/ressrf/go/ressrf` | `wazero`, `//go:embed core.wasm` | Rust `ressrf-core` (WASM) | Guaranteed bit-for-bit parity with the Rust core; security-strict consumers; willing to carry the wazero runtime weight; Go 1.26+ |
| `github.com/timescale/ressrf/go-native/ressrf` | Native Go on `net/netip` | Reimplemented in Go, pinned to WASM via diffuzz | Native debuggability (`pprof`/`delve` through the whole stack); zero WASM runtime weight; idiomatic Go API; split `httpx`/`tcpx`/`sshx` packages so non-SSH consumers do not pull `golang.org/x/crypto`; typed sealed-sum `DenyReason`; Go 1.25+ |

The native port consumes the same JSON conformance vectors and `crates/ressrf-core/config/` files as the wazero binding (no vendored copies), and additionally runs a differential-fuzz harness against the wazero binding's embedded `core.wasm` via `.github/workflows/diffuzz.yml`. Three parser-level divergences were caught and fixed via diffuzz during the native port's initial development; vectors alone would not have seen them.

Both bindings expose `DisableForTests` through a dedicated `ressrftest` subpackage so the `testing` import never reaches consumer production binaries:

```go
import "github.com/timescale/ressrf/go-native/ressrf/ressrftest"
// (or "github.com/timescale/ressrf/go/ressrf/ressrftest")

func TestSomething(t *testing.T) {
    ressrftest.DisableForTests(t) // auto-reverted via t.Cleanup
    // ...
}
```

### Installation

| Language | Command | Requirements |
|----------|---------|--------------|
| Rust | `cargo add ressrf-core` | Rust 1.75+ |
| Go (wazero) | `go get github.com/timescale/ressrf/go/ressrf` | Go 1.26+ |
| Go (native) | `go get github.com/timescale/ressrf/go-native/ressrf` | Go 1.25+ |
| Python | `pip install ressrf` | Python 3.10+ |
| Node.js | `npm install ressrf` | Node.js 20+ |

Add protocol adapters as needed:

```bash
# Rust: add HTTP or SSH crate
cargo add ressrf-http   # Tower Layer/Service
cargo add ressrf-ssh    # russh/async-ssh2 guard

# Python: optional extras
pip install ressrf[httpx]     # httpx transport
pip install ressrf[requests]  # requests adapter
pip install ressrf[ssh]       # paramiko guard
pip install ressrf[all]       # everything
```

The wazero Go binding and the Node.js package embed the WASM binary directly, so there are no additional native dependencies. The native Go port has no WASM runtime and splits its protocol adapters into `httpx`, `tcpx`, and `sshx` subpackages, so a consumer that imports only `httpx` or `tcpx` keeps `golang.org/x/crypto` out of its binary entirely. Node.js has optional peer dependencies on `undici` (>=8.2.0) and `ssh2` (>=1.17.0) for the HTTP and SSH protocol adapters.

### Architecture

```
                     ┌─────────────────────────┐                ┌──────────────────────┐
                     │      ressrf-core        │  shared JSON   │   go-native/ressrf   │
                     │  (policy, CIDR, URI,    │ config+vectors │   (native Go port)   │
                     │   audit, cloud, trie)   │ ─────────────▶ │  httpx / tcpx / sshx │
                     └───────┬─────────────────┘                └──────────┬───────────┘
                             │                                             │
           ┌─────────────────┼─────────────────┐                           │ diffuzz
           │                 │                 │                           │ vs core.wasm
           ▼                 ▼                 ▼                           ▼
   ┌────────────────┐ ┌─────────────┐  ┌────────────────┐         ┌──────────────────┐
   │  ressrf-wasm   │ │ ressrf-http │  │  ressrf-ssh    │         │  go/ressrf       │
   │  (WASM ABI)    │ │ (Tower)     │  │  (russh)       │         │  core.wasm       │
   └───────┬────────┘ └──────┬──────┘  └───────┬────────┘         │  oracle source   │
           │                 │                 │                  └──────────────────┘
     ┌─────┴─────┐           └───────┬─────────┘
     │           │                   │
     ▼           ▼                   ▼
┌─────────┐ ┌──────────┐      ┌──────────────┐
│Go(wazero│ │  Node.js │      │    Python    │
│  +WASM) │ │  (WASM)  │      │   (PyO3)     │
└─────────┘ └──────────┘      └──────────────┘
```

The Rust core (`ressrf-core`) is the reference implementation. The wazero Go binding and the Node.js binding both consume `ressrf-core` through the WASM ABI (`ressrf-wasm`). Data passes as JSON strings via linear memory, with each language managing alloc/dealloc through the exported functions. The wazero Go binding uses wazero with `//go:embed core.wasm`. Node.js uses the standard `WebAssembly` API with zero runtime dependencies.

Python takes a different path: PyO3/maturin compiles `ressrf-core` directly into a native extension module, avoiding WASM entirely. This gives Python the same performance as native Rust.

The native Go port (`go-native/ressrf/`) sits parallel to the main pipeline: it consumes only the shared JSON configuration (`crates/ressrf-core/config/*.json`) and conformance vectors (`tests/vectors/*.json`), never Rust code. It is pinned to `ressrf-core` via the `diffuzz.yml` workflow, which fuzzes the native Go engine against the wazero binding's `core.wasm` and fails on any allow/block divergence. There is no Rust toolchain in its build path, and no embedded WASM in the consumer's binary.

The WASM ABI exports: `policy_new`, `is_network_allowed`, `is_request_allowed`, `uri_in_domain`, `policy_free`, `set_audit_callback`, `alloc`, `dealloc`. A WIT file (`wit/ressrf.wit`) documents the ABI shape for Component Model compatibility.

For a deeper walkthrough of the architecture and how to extend ressrf with new cloud providers, language bindings, protocol adapters, or client library integrations, see [`HACKING.md`](https://github.com/timescale/ressrf/blob/main/HACKING.md).

### Security

**Deny-first by design.** The `ExternalOnly` preset blocks all IANA special-purpose ranges, cloud metadata endpoints, and link-local addresses before any connection is made. Unspecified addresses (0.0.0.0, ::) are always denied.

**Error::Blocked sentinel.** All rejection paths return a dedicated `Error::Blocked` variant (Rust), `ErrBlocked` (Go), `RessrfBlockedError` (Python), or `RessrfBlockedError` (Node.js). Callers use pattern matching or `errors.Is()`/`isinstance()`/`isBlocked()`, never string matching.

**Sensitive-data boundaries.** The library avoids logging credentials, connection strings, and request bodies. Structured errors and audit fields can include URLs, IPs, CIDRs, and deny reasons, so applications should not surface raw internal errors directly to untrusted end users.

**ReDoS-safe regex.** URL rule regex patterns use the Rust `regex` crate with a 1 MB automaton size limit, preventing catastrophic backtracking.

**Fuzz-tested.** Three cargo-fuzz targets (`fuzz_cidr`, `fuzz_policy`, `fuzz_url_validator`) run weekly in CI with seed corpora from handcrafted adversarial inputs. Eight native-Go fuzz targets (`ParseCIDR`, `ParseCIDRLoose`, `IsAmbiguousIP`, `ValidateURL`, `Policy`, `URLRulesEvaluate`, `GlobMatchHost`, `GlobMatchPath`) share the same weekly schedule. Crashes upload as artifacts.

**Differential fuzz across Go bindings.** `.github/workflows/diffuzz.yml` runs the native Go port against the wazero binding's `core.wasm` on every PR touching either parser, plus weekly. Any allow/block divergence fails the build; persisted divergence fixtures are replayed deterministically via `make fuzz-rust-regress`.

**Blind-spot fixes (BS-1..BS-6).** The URI validator hardens against octal/hex/decimal-integer/shorthand IPv4 hosts (BS-1), scheme-less and pseudo-scheme URLs (BS-2), NUL/CRLF parser-differential header injection (BS-3), trailing-dot suffix bypass (BS-4), backslash confusion (BS-5), and UNC paths (BS-6). All six are covered by the 92-case `ssrf_techniques.json` vector and the Tier 2 e2e suite under `crates/ressrf-tcp/tests/ssrf_e2e.rs`.

**IPv4-mapped-IPv6 bypass resistance.** The CIDR engine normalizes IPv4-mapped-IPv6 addresses (::ffff:127.0.0.1) and adjusts prefixes by +96, preventing bypass via address representation tricks.

**Userinfo bypass resistance.** The URI validator detects and rejects URL-encoded `%40` (`@`) in userinfo positions, preventing parser confusion attacks.

**Security reporting.** Security reports should use GitHub Private Advisories for `timescale/ressrf` or email `security@tigerdata.com` with the subject `[ressrf] Security Report`. The supported release line is `0.1.x`. In-scope issues include SSRF bypasses, DNS rebinding or TOCTOU bypasses, WASM/FFI memory safety issues, resource-exhaustion vulnerabilities, cross-language parity gaps, and supply-chain concerns.

**Accepted risks.** `bypass_ip_check: true` intentionally trusts matching URL allow rules and must be scoped narrowly. Regex matching is linear-time with a 1 MB automaton cap, but regex compilation time is still caller-controlled. Some audit and callback paths intentionally drop malformed events or callback errors rather than failing the protected request.

[v0.1.0](https://github.com/timescale/ressrf/commits/v0.1.0)

[0.1.0]: https://github.com/timescale/ressrf/releases/tag/v0.1.0
