# Changelog

All notable changes to ressrf are documented in this file.
Each entry corresponds to a [GitHub Release](https://github.com/timescale/ressrf/releases).

## [0.1.0] - TBD

**TL;DR**
First public multi-platform release of the library, shipping SSRF prevention across Rust, Go, Python, and Node.js:

- A fuzz-tested Rust core with deny-first policy engine, CIDR validation, IPv4-mapped-IPv6 normalization, and IANA-sourced default deny lists.
- Cloud provider modules for AWS (IMDS, ECS), Azure (IMDS, Wireserver, sovereign domains), and GCP (metadata, internal DNS).
- URL rules with host/path glob matching and ReDoS-safe regex, on top of IDN-safe URI validation with userinfo bypass resistance.
- Protocol adapters for HTTP (redirect re-validation), TCP (DNS-pinned dialing), and SSH in all four languages.
- Two co-existing Go bindings: a `wazero`-backed binding at `go/ressrf/` that runs the Rust core in WASM, and a native Go port at `go-native/ressrf/` with split `httpx`/`tcpx`/`sshx` subpackages and a typed sealed-sum `DenyReason`. Both share the same JSON conformance vectors and are pinned to the Rust core via a differential-fuzz harness.
- Pluggable audit logging with zero opinion on which logger to use, consistent across Rust, Go, Python, and Node.js.
- Automated IP ranges codegen from IANA, AWS, Azure, and GCP upstream sources, with a monthly CI refresh workflow.
- Cross-language conformance guaranteed by shared JSON test vectors, including a 92-case SSRF bypass taxonomy, plus multi-OS CI, Docker e2e tests, and a weekly diffuzz job.
- Published to crates.io, PyPI, npm, and two Go module tags (`go/ressrf/v0.1.0` and `go-native/ressrf/v0.1.0`).

### Deny-first policy engine

The core policy engine validates IP addresses and hostnames against configurable deny/allow CIDR lists with deny-first semantics. Three built-in presets cover common deployment patterns: `ExternalOnly` denies private/internal ranges and allows public internet (most common), `InternalOnly` allows only private/internal ranges, and `None` carries no default ranges and is fully custom via `add_allowed`/`add_denied`.

The default deny list ships in `crates/ressrf-core/config/ip_ranges.json`, sourced from IANA IPv4 and IPv6 special-purpose registries with hand-curated metadata and cloud-provider additions. It covers private use (RFC 1918), loopback, link-local, CGNAT (100.64.0.0/10), TEST-NETs, benchmarking, reserved/broadcast, IPv6 documentation, Teredo, 6to4, NAT64, and multicast ranges.

The CIDR engine handles IPv4-mapped-IPv6 normalization (adjusting the prefix by +96), rejects octal/hex IP representations and zone IDs, and supports edge cases including /0 and /128 prefixes. All unspecified addresses (0.0.0.0, ::) are denied by default. Protocol rules require HTTPS by default and deny plaintext HTTP unless a caller explicitly opts in; header rules can require or reject named headers before a request proceeds.

Allow overrides deny, so callers can punch holes for specific CIDRs while keeping the rest of private address space blocked.

### Cloud provider modules

Three cloud providers are supported out of the box. Each module contributes deny ranges for cloud metadata endpoints and domain suffix lists for internal services: AWS adds 169.254.169.254/32 (IMDS), 169.254.170.2/32 (ECS task metadata), fd00:ec2::254/128 (IMDSv2 IPv6), and `*.internal` / internal `amazonaws.com` suffixes. Azure adds 169.254.169.254/32 (IMDS), 168.63.129.16/32 (Wireserver/DHCP), plus `vault.azure.net`, `*.core.windows.net`, `*.database.windows.net`, `*.azurecr.io`, and sovereign variants (.cn/.de/.us). GCP adds 169.254.169.254/32 (metadata) plus `metadata.google.internal` and internal `*.internal` suffixes. Cloud deny ranges and domain lists are extracted into JSON config files (`crates/ressrf-core/config/domains_{aws,azure,gcp}.json`) and compiled into Rust constants at build time via `build.rs`.

### URI validation and URL rules

The URI validator provides protocol allowlisting (http/https/ws/wss by default), IDN-safe domain matching via `domainToASCII` with boundary-aware suffix checks, bare IP literal detection, and resistance to userinfo `@` bypass attacks (URL-encoded `%40`). Hostnames containing `--` are rejected to support cloud domain validators.

URL rules add URL-level allow/deny on top of CIDR-based filtering. Rules use glob patterns for host (`*` matches a single DNS label) and path (`*` matches a single segment, `**` matches any depth), with optional full-URL regex (1 MB automaton limit, ReDoS-safe via the `regex` crate). Deny rules are checked first. When allow rules are configured, URLs not matching any allow rule are blocked. Setting `bypass_ip_check: true` on an allow rule skips IP-level validation for trusted endpoints.

### Two Go bindings

This release ships two Go modules in the same repo, under one release cadence and the same `tests/vectors/` contract. Both live in-tree; neither is deprecated.

| Path | Runtime | Engine | Picking criteria |
|------|---------|--------|------------------|
| `github.com/timescale/ressrf/go/ressrf` | `wazero`, `//go:embed core.wasm` | Rust `ressrf-core` (WASM) | Bit-for-bit parity with the Rust core; willing to carry the wazero runtime weight; Go 1.26+ |
| `github.com/timescale/ressrf/go-native/ressrf` | Native Go on `net/netip` | Reimplemented in Go, pinned to WASM via diffuzz | Native debuggability through the whole stack; zero WASM runtime weight; idiomatic Go API; split `httpx`/`tcpx`/`sshx` packages so non-SSH consumers do not pull `golang.org/x/crypto`; typed sealed-sum `DenyReason`; Go 1.25+ |

The native port consumes the same JSON conformance vectors and `crates/ressrf-core/config/` files as the wazero binding (no vendored copies), and additionally runs a differential-fuzz harness against the wazero binding's embedded `core.wasm` via `.github/workflows/diffuzz.yml`. Three parser-level divergences were caught and fixed via diffuzz during the native port's initial development; vectors alone would not have seen them.

Both bindings expose `DisableForTests` through a dedicated `ressrftest` subpackage (`go/ressrf/ressrftest/`, `go-native/ressrf/ressrftest/`) so the `testing` import never reaches consumer production binaries. An `internal/testbypass/` package holds the shared atomic bypass flag.

### Protocol adapters

Protocol adapters integrate at DNS resolution and connection establishment, providing transparent SSRF protection for HTTP, TCP, and SSH in all four languages. Every adapter validates resolved IP addresses against the policy before allowing the connection to proceed.

| Protocol | Rust | Go (wazero) | Go (native) | Python | Node.js |
|----------|------|-------------|-------------|--------|---------|
| HTTP | Tower Layer/Service with redirect re-validation per hop; DNS pinning comes from `ressrf-tcp::SafeConnector` | `policy.HTTPTransport(base)` returning `http.RoundTripper`, redirect re-validation at CheckRedirect + Control hook | `httpx` subpackage: `http.RoundTripper` + `http.Client` with per-request DNS and redirect-hop validation | httpx `SafeTransport`/`AsyncSafeTransport`, requests `SafeAdapter` | `httpAgent`/`httpsAgent` with DNS validation, `safeFetch` with redirect re-validation, `undiciConnect` for undici |
| TCP | `policy.tcp_connect(addr)` async | `SafeDialer` with `net.Dialer.Control` hook, 30s default timeout | `tcpx` subpackage: `net.Dialer` with `Control` hook validating resolved IPs | `safe_getaddrinfo`, `create_connection` | `createConnection` returning policy-validated `net.Socket`, `dnsLookup` override |
| SSH | Guard wrapper for russh/async-ssh2 | `policy.SSHDial(ctx, addr, sshConfig)` wrapping `ssh.NewClientConn` | `sshx` subpackage: SSH dial wrapping `golang.org/x/crypto/ssh` (only `sshx` pulls that dependency) | `safe_ssh_connect` via paramiko | `safeSshConnect` via ssh2 `sock` option |

HTTP adapters are the most involved because they must re-validate on every redirect hop.

### Pluggable audit logging

All bindings expose the same pluggable audit interface. The core audit model defines structured `AuditEvent` values (`HostValidated`, `UrlValidated`, `ConnectionAttempt`, `RedirectIntercepted`, `PolicyCreated`) with optional detection fields: `raw_input`, `match_reason`, `caller_context`, and `policy_version`. The library never dictates which logging framework to use, and when no sink is configured the overhead is zero. Each language exposes the same surface (interface, `AuditFunc` callback adapter, `MultiSink`, `DiscardSink`), and Rust additionally ships `ressrf-tracing` for ready-made `tracing::event!` emission with structured `ressrf.*` fields.

### IP ranges codegen

`scripts/generate_ip_ranges.py` is a stdlib-only Python script that fetches upstream IP range data from IANA IPv4/IPv6 special-purpose registry CSVs, AWS `ip-ranges.json`, Azure ServiceTags JSON (rotating URL discovery), and GCP `cloud.json`/`goog.json`. It supports `--iana-only`, `--validate-only`, and `--dry-run`, with SHA-256 audit logging, CIDR validation, duplicate detection, and a `csp_metadata` cross-check against provider deny_ranges.

A `ServiceRangeTable` provides trie-backed O(log n) longest-prefix-match lookups via the `prefix-trie` crate (gated behind the `std` feature). It integrates with `PolicyBuilder` via optional `with_service_ranges()`. A monthly CI workflow (`.github/workflows/update-ip-ranges.yml`, 1st of each month) fetches upstream data, runs `--validate-only` and `cargo test`, and opens a PR automatically on changes.

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

Additional quality gates: `cargo fmt --check` + `cargo clippy -D warnings`, `cargo test --workspace --all-features` (multi-OS), `cargo build --target wasm32-wasip1` + `wasm-opt`, `go test -race ./...` (multi-OS) + `go vet` + `golangci-lint` for both Go modules, `pytest` (multi-OS) + `ruff` + `ty`, `node:test` (multi-OS) + `tsc --noEmit`, plus daily `cargo audit` + `govulncheck` (matrixed across both Go modules), weekly `cargo-fuzz` (3 Rust targets) and `fuzz-go-native` (8 Go targets), weekly `diffuzz` (native Go vs WASM oracle), and `zizmor --pedantic` on every workflow change. Dependabot tracks Cargo, both Go modules, Python (uv), Node (npm), and GitHub Actions in separate update groups.

The Tier 2 e2e suite lives under `crates/ressrf-tcp/tests/ssrf_e2e.rs` and uses shared container assets in `tests/containers/` (CoreDNS + WireMock). It is gated behind the `e2e` Cargo feature and requires Docker.

### Blind-spot fixes (BS-1..BS-6)

The URI validator hardens against six classes of bypass before reaching the network layer:

- BS-1: Octal/hex/decimal-integer/shorthand IPv4 hosts (`0177.0.0.1`, `0x7f000001`, `2130706433`, `127.1`) -> `DenyReason::AmbiguousIpEncoding`
- BS-2: Scheme-less and pseudo-scheme URLs (`javascript:alert(1)`, `data:...`, `http:host/path`, bare hostnames) -> `DenyReason::SchemeRequired`
- BS-3: NUL/CRLF (raw and `%00`/`%0d`/`%0a`) parser-differential header injection
- BS-4: Trailing-dot (`metadata.google.internal.`) suffix bypass
- BS-5: Backslash confusion (`http://127.0.0.1\@trusted.com/`)
- BS-6: UNC `\\host\share` URLs -> `DenyReason::UrlParseError`

All six are covered by the 92-case `ssrf_techniques.json` vector and the Tier 2 e2e suite.

### Rust crates

| Crate | Description |
|-------|-------------|
| `ressrf-core` | Policy engine, CIDR validation, URI validator, cloud modules, audit types, URL rules, IP range trie |
| `ressrf-tcp` | DNS-pinned async TCP dialing with policy validation at resolve time |
| `ressrf-http` | Tower Layer/Service with redirect re-validation per hop |
| `ressrf-ssh` | Guard wrapper for russh/async-ssh2 with pre-validated SocketAddr |
| `ressrf-tracing` | TracingSink audit adapter emitting `tracing::event!` with structured `ressrf.*` fields |
| `ressrf-wasm` | Thin WASM ABI wrapper exporting policy/validation functions; `publish = false` |

The first five crates are published to crates.io. `ressrf-wasm` produces the `.wasm` binary embedded by the wazero Go binding and the Node.js binding, and acts as the differential-fuzz oracle for the native Go port.

### Installation

| Language | Command | Requirements |
|----------|---------|--------------|
| Rust | `cargo add ressrf-core` | Rust 1.75+ |
| Go (wazero) | `go get github.com/timescale/ressrf/go/ressrf` | Go 1.26+ |
| Go (native) | `go get github.com/timescale/ressrf/go-native/ressrf` | Go 1.25+ |
| Python | `pip install ressrf` | Python 3.10+ |
| Node.js | `npm install ressrf` | Node.js 20+ |

Node.js has optional peer dependencies on `undici` (>=8.2.0) and `ssh2` (>=1.17.0) for the HTTP and SSH protocol adapters. Python has optional extras (`ressrf[httpx]`, `ressrf[requests]`, `ressrf[ssh]`, `ressrf[all]`).

### Security properties

- Deny-first by design: `ExternalOnly` blocks all IANA special-purpose ranges, cloud metadata endpoints, and link-local addresses before any connection is made.
- `Error::Blocked` sentinel: rejection paths return a dedicated typed variant in every language (`ErrBlocked` in Go, `RessrfBlockedError` in Python and Node.js).
- ReDoS-safe regex: URL rule regex patterns use the Rust `regex` crate with a 1 MB automaton size limit.
- Fuzz-tested: 3 cargo-fuzz targets and 8 native-Go fuzz targets run weekly in CI. Differential fuzz across the two Go bindings runs weekly and per-PR.
- IPv4-mapped-IPv6 bypass resistance: the CIDR engine normalizes IPv4-mapped-IPv6 addresses (::ffff:127.0.0.1) and adjusts prefixes by +96.
- Userinfo bypass resistance: the URI validator rejects URL-encoded `%40` (`@`) in userinfo positions.
- Security reporting via GitHub Private Advisories on `timescale/ressrf` or `security@tigerdata.com` (subject `[ressrf] Security Report`). Supported release line: `0.1.x`.

### Documentation

- `HACKING.md` at repo root: contributor and developer guide covering project setup, building, testing, and step-by-step instructions for adding new cloud providers, language bindings, protocol adapters, and client library integrations.
- `THREAT_MODEL.md`: STRIDE matrix, trust boundary diagram, prioritized threat scenarios, accepted risks.
- `SECURITY.md`: vulnerability reporting policy, supported versions, security contact.
- Per-package READMEs for every crate, the Go bindings, Python package, and Node.js package.

[v0.1.0](https://github.com/timescale/ressrf/commits/v0.1.0)

[0.1.0]: https://github.com/timescale/ressrf/releases/tag/v0.1.0
