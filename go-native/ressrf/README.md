# ressrf (Go)

Go package for SSRF prevention, implemented natively in Go. Zero CGO. The default IANA + cloud-metadata deny list is compiled in.

The semantics mirror the Rust [`ressrf-core`](../../crates/ressrf-core/) engine (URI parsing blind-spots BS-1..BS-6, deny-first URL rules, allow-overrides-deny CIDR precedence, ambiguous-IP rejection); cross-language conformance is enforced by the JSON vectors under `../../tests/vectors/`.

See [`docs/how-it-works.md`](docs/how-it-works.md) for an end-to-end walkthrough from the JSON spec to a blocked SSRF attempt.

## Relationship to the sibling wazero binding

The workspace also ships a [wazero-backed Go binding](../../go/ressrf/) that runs the Rust core in a WASM sandbox. Both packages compile against the same `../../tests/vectors/` contract. This package is a native Go port: no WASM runtime, no embedded `.wasm`, no Rust toolchain in the build pipeline.

| Surface | This package (native) | Sibling wazero binding |
|---|---|---|
| Engine | Native Go on `net/netip` + `regexp` | `wazero` calling into `ressrf-core.wasm` |
| Build dependency | none | embedded `core.wasm`, rebuilt via `build_wasm.sh` |
| Constructor | `NewPolicy(preset, opts...)` (deny-only) and `NewAllowListPolicy(preset, allowed, opts...)` (allow-list); allow-list mode is a constructor choice, no Option can flip it | `PolicyBuilder.WithX().Build(ctx)` chained builder; allow-list mode set implicitly by `with_trusted_suffixes` non-emptiness |
| `Preset` type | typed `uint8` iota | `string` constants |
| Block reason | sealed-sum `DenyReason` (type-switchable) | `string` field |
| Redirect downgrade | typed `*RedirectSchemeDowngrade` | string literal |
| Protocol adapters | split packages (`httpx`, `sshx`, `tcpx`) | flat package |
| Optional crypto dep | only `sshx` pulls `golang.org/x/crypto` | always imported |
| Policy lifecycle | no `Close()` needed | `Build(ctx)` + `Policy.Close(ctx)` |
| Domain-suffix surface | `WithDeniedDomainSuffixes` (additive deny); allow-list seed via `NewAllowListPolicy` constructor parameter; cloud-provider service suffixes available as data via `CloudServiceSuffixes(providers...)` | reachable only via cloud-provider modules, which bundle deny-and-trust |

Cross-language conformance is preserved end to end: both bindings consume the same 8 JSON vector files at `../../tests/vectors/`, the BS-1..BS-6 URI validator, deny-first / allow-overrides-deny precedence, and the same cloud-provider and IANA deny ranges. The generator under `internal/cmd/gen-data` reads `../../crates/ressrf-core/config/*.json` so both the WASM-backed binding and this native port pick up upstream IP-range refreshes from a single source.

A differential-fuzz harness (`make fuzz-rust`, documented below) runs random URLs through both engines and fails on any allow/block divergence, catching parser drift the vectors cannot see. It surfaced 3 parser-level divergences during the initial port, all fixed and committed as regression fixtures.

## Packages

| Import path | Purpose |
|---|---|
| `github.com/timescale/ressrf/go-native/ressrf` | Policy builder, `Policy`, `BlockedError`, `DenyReason` variants |
| `github.com/timescale/ressrf/go-native/ressrf/httpx` | `http.RoundTripper` + `http.Client` with policy enforcement on every request, DNS resolution, and redirect hop |
| `github.com/timescale/ressrf/go-native/ressrf/tcpx` | `net.Dialer` with a `Control` hook that validates resolved IPs |
| `github.com/timescale/ressrf/go-native/ressrf/sshx` | SSH dial wrapping `golang.org/x/crypto/ssh` (only `sshx` pulls that dependency) |

The packages are split so consumers only pay the dependency cost of what they actually call. Only `sshx` imports `golang.org/x/crypto/ssh`; an application that only needs HTTP or raw-TCP protection imports `httpx` or `tcpx` and keeps `golang.org/x/crypto` out of its binary entirely.

See the Go examples on [pkg.go.dev](https://pkg.go.dev/github.com/timescale/ressrf/go-native/ressrf) (or `go doc -all .` locally) for `NewPolicy`, `URLRuleGlob` / `URLRuleRegex`, `Policy.IsAllowed`, structured-rejection type switches, and `AuditSink` wiring.

## Test bypass

```go
func TestSomething(t *testing.T) {
    ressrf.DisableForTests(t) // auto-reverted via t.Cleanup
    // ... policy checks become no-ops for the rest of this test
}
```

Production code cannot flip the bypass: the setter is gated on `testing.TB`.

## Differential fuzz vs the Rust oracle

`internal/diff/` hosts a differential-fuzz harness that compares this native Go engine against the Rust `ressrf-core` compiled to WASM. Gated behind the `diffuzz` build tag so wazero and the `.wasm` artifact stay out of the default build path.

```bash
make fuzz-rust          # fuzzes for 5m (override with FUZZ_RUST_DURATION=30s)
```

The oracle WASM is the sibling [wazero binding's](../../go/ressrf/) checked-in `core.wasm` — same artifact `wazero` loads in production, post-processed by `wasm-opt -Oz` + `wasm-tools strip`. No clone, no cargo step; the harness picks the file up via `runtime.Caller`.

The harness compares the boolean allow/block decision under `PresetExternalOnly`. Reason taxonomy is not compared because cross-language reason strings drift cosmetically; the security-relevant signal is the binary outcome.
