# Threat Model

This document describes the threat model for ressrf, a multi-platform SSRF prevention library. It covers trust boundaries, a STRIDE analysis per component, prioritized threat scenarios, and accepted risks.

## Trust Boundaries

```
                            ┌─────────────────────────────────────┐
                            │        Application Code             │
                            │  (untrusted URLs, IPs, CIDRs,       │
                            │   cloud provider names, regexes)    │
                            └───────────┬─────────────────────────┘
                                        │ TB-1: Application Input
    ┌───────────────────────────────────┼───────────────────────────────────┐
    │                                   ▼                                   │
    │  ┌──────────────────────────────────────────────────────────────┐     │
    │  │                     ressrf-core (Rust)                       │     │
    │  │  PolicyBuilder, Policy, UriValidator, CidrSet, UrlRuleset    │     │
    │  │  AuditSink trait, AuditEvent, CloudProvider                  │     │
    │  └──────────┬──────────────┬───────────────┬────────────────────┘     │
    │             │              │               │                          │
    │    TB-2a    │     TB-2b    │     TB-2c     │                          │
    │    WASM     │     PyO3     │     Native    │                          │
    │    ABI      │     FFI      │     Rust      │                          │
    │     ▼       │      ▼       │       ▼       │                          │
    │  ┌──────┐ ┌──────┐ ┌───────────────────────────────────┐              │
    │  │ WASM │ │Python│ │  ressrf-tcp / ressrf-http / ssh   │              │
    │  │      │ │      │ │  SafeResolver, SafeConnector      │              │
    │  └──┬───┘ └──────┘ │  SsrfLayer, RedirectValidator     │              │
    │     │              └────────────┬──────────────────────┘              │
    │     │                           │ TB-3: Network I/O                   │
    └─────┼───────────────────────────┼─────────────────────────────────────┘
          │                           ▼
    ┌─────┼────────┐        ┌──────────────────┐
    │  Go / Node   │        │   DNS Resolver   │ TB-4: DNS Responses
    │  WASM hosts  │        │  (untrusted)     │
    │  (wazero /   │        └──────────────────┘
    │  WebAssembly)│
    └──────────────┘
```

### TB-1: Application Input

The library consumer provides URLs, IP addresses, CIDR strings, cloud provider names, URL rule regexes, header names, and domain suffixes. All of these are untrusted input that the library must validate or safely reject.

### TB-2a: WASM ABI (Go and Node.js)

JSON is serialized across WASM linear memory via raw pointer/length pairs. The host (Go wazero or Node.js WebAssembly API) controls all memory writes. The guest (Rust WASM module) trusts pointer/length pairs from the host, bounded by WASM's linear memory sandbox. Host-to-guest audit callbacks cross this boundary in the reverse direction.

### TB-2b: PyO3 FFI (Python)

Python callbacks are bridged into Rust via `Py<PyAny>` reference-counted handles with `unsafe impl Send + Sync`. The GIL serializes access to Python objects but the Rust side must guarantee the callback handle outlives any Rust references to it.

### TB-2c: Native Rust Protocol Adapters

`ressrf-tcp`, `ressrf-http`, and `ressrf-ssh` link `ressrf-core` directly. No serialization boundary, but they interact with the OS network stack (DNS, TCP sockets) which produces untrusted data.

### TB-3: Network I/O (DNS and TCP)

DNS responses are untrusted. An attacker can control DNS records to return internal IP addresses (DNS rebinding) or rotate answers between calls (TOCTOU). TCP connections must be made to the exact IP that passed policy validation.

### TB-4: Build-time Config

`config/ip_ranges.json` and `config/domains_*.json` are consumed by `build.rs` at compile time. Runtime `ServiceRangeTable::load_from_file` trusts the local filesystem. The monthly `update-ip-ranges.yml` CI workflow fetches upstream IANA and CSP data.

---

## STRIDE Analysis

### ressrf-core (Policy Engine, CIDR Parser, URI Validator, URL Rules)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | Yes | Ambiguous IP encodings (octal/hex/decimal/shorthand) could spoof the identity of a destination. Mitigated by `is_ambiguous_ip()` rejection and `parse_ip_strict()` throughout. |
| **Tampering** | No | Policy is immutable after `build()`. No external mutation path. |
| **Repudiation** | Low | AuditSink emits structured events for policy decisions. If no sink is configured, decisions are not logged. Silent error-dropping in audit paths reduces audit completeness. |
| **Info Disclosure** | Low | Error messages include IP addresses and CIDR ranges in `DenyReason` variants. If surfaced to end users, this leaks internal network topology. |
| **DoS** | Medium | URL rule regex automaton capped at 1 MB but compile time is unbounded. No cap on CIDR list size. |
| **EoP** | No | Library runs at the caller's privilege level. |

### ressrf-tcp (SafeResolver, SafeConnector)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | Mitigated | DNS rebinding prevented by resolve-once-pin: `SafeResolver` resolves, validates every IP, and `SafeConnector` connects to the validated IP directly without re-resolving. |
| **Tampering** | No | The resolved IP list is not externally mutable between resolve and connect. |
| **Repudiation** | Low | Non-`Blocked` errors in resolver are logged at debug level but not propagated to audit. |
| **Info Disclosure** | No | DNS queries and TCP connections are standard, no credential leakage. |
| **DoS** | Low | `collect()` on DNS results has no explicit cap, but OS resolvers typically return small result sets. 30-second connect timeout bounds SYN-blackhole waits. |
| **EoP** | No | |

### ressrf-http (SsrfLayer, SsrfService, RedirectValidator)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | Mitigated | Per-hop redirect re-validation via `validate_hop()` catches redirects to internal endpoints. Hostname-based redirect targets are re-validated at the TCP layer when `SafeConnector` resolves and connects (defense in depth, see BS-7 design note). |
| **Tampering** | No | |
| **Repudiation** | Medium | `validate_hop` discards the inner `validate_url` error, replacing it with a generic `RedirectBlocked`. This loses the specific deny reason for audit. |
| **Info Disclosure** | No | |
| **DoS** | Low | Max redirects capped at 10 (configurable). |
| **EoP** | No | |

### ressrf-ssh (SafeSshConnector)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | Mitigated | SSH connections go through `SafeConnector`, inheriting the resolve-once-pin guarantee. |
| **Tampering** | No | |
| **Repudiation** | No | |
| **Info Disclosure** | No | |
| **DoS** | Low | Timeout inherited from `SafeConnector`. |
| **EoP** | No | |

### ressrf-wasm (WASM ABI)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | No | WASM sandbox prevents the guest from accessing host resources. |
| **Tampering** | No | WASM linear memory is sandboxed. |
| **Repudiation** | Medium | Audit event serialization failure silently drops events (`serde_json::to_vec` returns `Err`, event discarded). |
| **Info Disclosure** | No | WASM sandbox isolates guest memory. |
| **DoS** | Medium | `static mut POLICIES` vec grows without bound (no cap on policy count, no slot reuse). Unbounded `PolicyConfig` JSON fields also create allocation risk. |
| **EoP** | No | WASM sandbox prevents this. |

### ressrf-tracing (TracingSink)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | No | |
| **Tampering** | No | |
| **Repudiation** | No | Events are emitted through the standard `tracing` infrastructure. |
| **Info Disclosure** | Low | Structured fields include IPs and URLs. Log access controls are the operator's responsibility. |
| **DoS** | No | |
| **EoP** | No | |

### Go Package (wazero host, protocol adapters)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | Medium | Go previously had protocol adapter gaps where `controlFunc` and `SSHDial` used synthetic URL schemes rejected by the URI validator, and `HTTPTransport` could call an existing dialer after only URL-level validation. These were fixed in S1. |
| **Tampering** | No | |
| **Repudiation** | Medium | `hostAuditEvent` silently drops malformed JSON from WASM. `json.Marshal` error ignored in `IsAllowed`. |
| **Info Disclosure** | No | |
| **DoS** | Low | Bounded by WASM instance lifetime and Go garbage collection. |
| **EoP** | No | |

### Python Package (PyO3 bridge)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | No | |
| **Tampering** | No | |
| **Repudiation** | Low | Python audit callback errors are silently ignored (`let _ = self.callback.call1(...)`). |
| **Info Disclosure** | No | |
| **DoS** | No | Python links `ressrf-core` natively, no WASM overhead. |
| **EoP** | No | |

### Node.js Package (WASM host)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | No | |
| **Tampering** | No | |
| **Repudiation** | Low | Audit callback catches JSON parse errors and silently drops them. |
| **Info Disclosure** | No | |
| **DoS** | Low | Same WASM-level DoS considerations as Go. |
| **EoP** | No | |

### CI/CD (Supply Chain)

| Threat | Applies | Analysis |
|--------|---------|----------|
| **Spoofing** | Mitigated | All GitHub Actions pinned by full SHA with version comments. `persist-credentials: false` on all non-push checkout steps. |
| **Tampering** | Medium | WASM auto-commit in `build-wasm` job pushes `core.wasm` changes on `main`/PR branches with `persist-credentials: true`. A compromised dependency could alter the WASM binary. IP ranges codegen fetches from upstream IANA/CSP endpoints; a poisoned upstream could inject malicious CIDR ranges. |
| **Repudiation** | Mitigated | CI logs are retained by GitHub. |
| **Info Disclosure** | No | |
| **DoS** | Low | Concurrency groups prevent parallel runs. |
| **EoP** | Mitigated | Least-privilege permissions per job. `zizmor --pedantic` enforces workflow security. |

---

## Prioritized Threat Scenarios

### Critical (bypass = SSRF)

1. **DNS rebinding (TOCTOU)**: Attacker controls DNS to return different IPs on successive queries. **Mitigated** by resolve-once-pin in `SafeResolver`/`SafeConnector`. E2E testcontainers verify this.
2. **Redirect chain to internal endpoint**: HTTP 302 to `http://169.254.169.254/`. **Mitigated** by `RedirectValidator` per-hop re-validation + `SafeConnector` TCP-layer check.
3. **IPv6/IPv4-mapped address tricks**: `http://[::ffff:169.254.169.254]/`. **Mitigated** by CIDR engine IPv6 normalization with +96 prefix adjustment.
4. **Ambiguous IP encodings**: `http://2130706433/` (decimal), `http://0177.0.0.1/` (octal). **Mitigated** by `is_ambiguous_ip()` in URI validator (BS-1 fix).
5. **URL parser inconsistency**: Backslash confusion, null bytes, CRLF. **Mitigated** by BS-3/BS-5 fixes.
6. **Go protocol adapter gaps**: TCP, SSH, and HTTP transport paths previously had mismatched URL-level validation or skipped IP-level validation in some paths. **Status**: Fixed in S1 by moving TCP enforcement to `IsNetworkAllowed`, proxying SSH URL-level checks through `https://`, and forcing HTTP dials through the safe dialer.
7. **`bypass_ip_check: true` misconfiguration**: A URL allow rule with `bypass_ip_check` allows any IP for matching URLs. **Accepted risk**: This is an intentional feature for trusted endpoints. Documentation warns about misuse.

### High (DoS / resource exhaustion)

8. **WASM policy handle leak**: Creating policies without freeing them grows the `POLICIES` vec without bound.
9. **Unbounded `PolicyConfig` JSON fields**: No cap on `allow_cidrs`/`deny_cidrs`/`cloud_providers` array lengths in WASM deserialization.
10. **Regex compile time**: URL rule regex automaton capped at 1 MB but regex compilation time is not bounded.

### Medium (information disclosure / audit gaps)

11. **Swallowed errors**: Errors dropped in resolver, redirect validator, WASM audit, Go audit, Python audit. Audit visibility gap.
12. **Error message IP leakage**: `DenyReason` variants include IP addresses and CIDR ranges. If surfaced to end users, leaks internal topology.

### Low (defense in depth)

13. **`static mut POLICIES`**: Sound for single-threaded WASM today. If the WASM threading proposal is adopted, this becomes unsound.
14. **`PolicyBuilder::build()` panic**: Panics on invalid URL rule regex instead of returning error. `try_build()` is available as a fallible alternative.
15. **`Layout::from_size_align().unwrap()`**: In `ressrf_alloc`/`ressrf_dealloc`. Can only fail for sizes exceeding `isize::MAX`, which is unreachable in wasm32 linear memory.

---

## Accepted Risks

| Risk | Rationale |
|------|-----------|
| `bypass_ip_check: true` allows arbitrary IPs for matching URLs | Intentional feature for trusted-endpoint patterns. Documented in README. |
| `RedirectValidator::validate_hop` does not DNS-resolve hostname redirect targets | By design (BS-7). DNS resolution is async; redirect hooks are synchronous. Defense in depth via `SafeConnector` at TCP layer. |
| No rate limiting on policy evaluation APIs | Rate limiting is the caller's responsibility. The library is designed for embedding, not as a standalone service. |
| Error messages include IPs/CIDRs in `DenyReason` | Callers must sanitize error messages before exposing to end users. The structured `DenyReason` enum enables this. |
| `static mut` in WASM crate | WASM is single-threaded today. If the WASM threading proposal ships, the crate must migrate to `thread_local!` or atomics. |
| Monthly IP ranges update trusts upstream IANA/CSP sources | The codegen script validates CIDR syntax and runs `cargo test` before the PR is opened. Human review required before merge. |
