# ressrf-static

A pure-Go SSRF evaluator, behaviorally identical to [`go/ressrf`][wasm] but
without the wazero WASM runtime. Policy data ships as embedded JSON taken
verbatim from `crates/ressrf-core/config/`; the evaluation algorithms are
re-implemented in Go.

## When to prefer this over `go/ressrf`

- **No CGO, no WASM runtime** — `go list -m -deps` shows zero ressrf-specific
  dependencies beyond `golang.org/x/crypto` (for SSH).
- **Native speed** — `IsAllowed` runs in ~1.3 µs vs ~75 µs through WASM; build
  cost is ~55 µs vs ~150 ms (one-shot CLIs benefit a lot).
- **Smaller binaries** — no embedded ~1 MB `core.wasm`.

## When to prefer the WASM-backed package

- **Cross-language conformance is load-bearing.** ressrf-static is a port of
  the Rust core; any SSRF bypass discovered in `ressrf-core` has to be patched
  here separately. The Task 12 parity gate (`TestParityIPLevel` /
  `TestParityURLLevel`, 129 cases) is the only thing keeping them in lockstep.
  If you're paranoid, use the WASM package — bypass fixes land in one place.

## Quick start

```go
import "github.com/timescale/ressrf/go/ressrf-static"

p, err := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
    WithCloudProviders("aws", "gcp").
    Build()
if err != nil { /* bad CIDR / bad regex */ }

// URL-level (scheme allowlist + URI structural + bare-IP IP check)
if err := p.IsAllowed(ctx, "http://169.254.169.254/"); err != nil {
    // *ressrfstatic.BlockedError; errors.Is(err, ressrfstatic.ErrBlocked) → true
}

// IP-level (used internally by the dialer Control hook)
err = p.IsNetworkAllowed([]string{"10.0.0.1"}) // → blocked

// SSRF-safe HTTP client
client := p.HTTPClient(nil)
resp, err := client.Get("https://example.com/")

// SSRF-safe TCP dialer for arbitrary protocols
dialer := p.SafeDialer()
conn, err := dialer.DialContext(ctx, "tcp", "host:port")

// SSRF-safe SSH dial (defense in depth: URL-layer + post-DNS IP check)
sshClient, err := p.SSHDial(ctx, "host:22", sshClientConfig)
```

The public API mirrors `go/ressrf` so callers can swap imports in most cases.

## Architecture

```
PolicyBuilder
    │
    ▼
Build() ─────► [preset deny tiers from embedded ip_ranges.json]
            ─► [cloud deny CIDRs from embedded domains_{aws,azure,gcp}.json]
            ─► [user-supplied allow/deny CIDRs]
            ─► [URL ruleset compilation — Go regexp/RE2]
            ─► Policy
                 │
                 ├─ IsAllowed(url):
                 │     1. URL rules (deny first, allow w/ optional BypassIPCheck)
                 │     2. URI validator (scheme, userinfo, suffix, control-chars)
                 │     3. Bare-IP path → IsNetworkAllowed
                 │
                 └─ IsNetworkAllowed(ips):
                       per-preset allow/deny semantics
```

All policy data is embedded at compile time via `//go:embed config/*.json`.
Vector files used by tests live in `testdata/vectors/`.

## Maintaining the embedded policy data

The canonical data sources live under `crates/ressrf-core/config/` and are
refreshed monthly by the existing Python generator:

```
python scripts/generate_ip_ranges.py
```

After the canonical files change, refresh the Go-side copies and commit:

```
go generate ./go/ressrf-static/...
git add go/ressrf-static/config/
```

CI runs `go generate` and `git diff --exit-code go/ressrf-static/config/`
to fail PRs that forgot the second step.

## Test coverage

All cross-language conformance vectors at `tests/vectors/*.json` are wired
into Go tests:

| Vector file | Cases | Runner |
|---|---:|---|
| `cidr_containment.json` | 53 | `TestCIDRContainmentVectors` |
| `ipv4_ipv6_mapping.json` | 7 | `TestIPv4IPv6MappingVectors` |
| `url_validation.json` | 21 | `TestURLValidationVectors` |
| `url_rules.json` | 14 | `TestURLRulesVectors` |
| `policy_decisions.json` | 37 | `TestPolicyDecisionVectors` |
| `redirect_chains.json` | 12 | `TestRedirectChainVectors` |
| `ssrf_techniques.json` | 92 | `TestParityURLLevel` (+ TestURIValidatorUnitSmokes) |
| `audit_events.json` | 10 | `TestAuditEventVectors` |

The Task 12 parity gate (`TestParityIPLevel` + `TestParityURLLevel`,
129 cases) confirms WASM-backend and native-backend agree on every case.

```
$ go test ./go/ressrf-static/...
ok  github.com/timescale/ressrf/go/ressrf-static  1.5s
```

## Benchmarks

Apple M1 Max, Go 1.26:

```
BenchmarkPolicyBuild           21559    55_122 ns/op   14697 B/op    243 allocs/op
BenchmarkIsAllowed            896644     1_291 ns/op     736 B/op     14 allocs/op
BenchmarkIsAllowedBlocked    1617927       740 ns/op     448 B/op      6 allocs/op
BenchmarkIsNetworkAllowed   2651221       451 ns/op     128 B/op      2 allocs/op
```

For comparison, the WASM-backed `go/ressrf` package on the same hardware:

```
BenchmarkPolicyBuild              2  147_617_312 ns/op  34_468_864 B/op  47_638 allocs/op
BenchmarkIsAllowed                2       75_834 ns/op       1_720 B/op       37 allocs/op
BenchmarkIsAllowedBlocked         2       40_958 ns/op         680 B/op       17 allocs/op
BenchmarkIsNetworkAllowed         2       22_521 ns/op       1_168 B/op       28 allocs/op
```

So roughly 50–60× faster on per-check operations and three orders of magnitude
faster on policy construction (since there's no WASM module to load).

## Caveats / non-goals

- **Cloud modules add deny CIDRs only**, matching WASM ABI behavior. For
  domain-level cloud denial, opt in via:
  ```go
  suffixes, _ := ressrfstatic.CloudDeniedSuffixesFor("aws")
  b.WithCloudProviders("aws").WithDeniedSuffixes(suffixes...)
  ```
- **Regex URL rules** are compiled with Go `regexp` (RE2). Same linear-time
  guarantees as the Rust `regex` crate; some Rust-specific Unicode classes may
  not transfer. Add a vector if you find a divergence.
- **Audit sink shape differs from `go/ressrf`** — this package uses typed event
  variants (`HostValidated`, `URLValidated`, etc.) while `go/ressrf` ships a
  single flat `AuditEvent{Kind, Fields json.RawMessage}` struct. Both implement
  the spirit of `crates/ressrf-core/src/audit.rs`; pick whichever fits your
  logging stack.

[wasm]: ../ressrf/README.md
