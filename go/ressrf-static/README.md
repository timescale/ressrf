# ressrf-static

A pure-Go SSRF evaluator, behaviorally identical to [`go/ressrf`][wasm] but
without the wazero WASM runtime. Policy data ships as embedded JSON taken
verbatim from `crates/ressrf-core/config/`; the evaluation algorithms are
re-implemented in Go.

## When to prefer this over `go/ressrf`

- **No CGO, no WASM runtime** — `go list -m -deps` shows zero ressrf-specific
  dependencies beyond `golang.org/x/crypto` (for SSH).
- **Smaller binaries** — no embedded ~1 MB `core.wasm`, no wazero (~1 MB of
  Go code).
- **Faster** — per-check operations are ~2–4× faster than the WASM-backed
  package; `PolicyBuild` is ~140× faster (one-shot CLIs benefit). Numbers
  below.

## When to prefer the WASM-backed package

- **Cross-language conformance is load-bearing.** ressrf-static is a port of
  the Rust core; any SSRF bypass discovered in `ressrf-core` has to be patched
  here separately. The Task 12 parity gate (`TestParityIPLevel` /
  `TestParityURLLevel`, 129 cases) is the only thing keeping them in lockstep.
  If you're paranoid, use the WASM package — bypass fixes land in one place.

## Quick start

```go
import (
    "github.com/timescale/ressrf/go/ressrf-static"
    "github.com/timescale/ressrf/go/ressrf-static/cloud/aws" // only the providers you need
    "github.com/timescale/ressrf/go/ressrf-static/cloud/gcp"
)

p, err := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
    WithCloudModule(aws.Module()).
    WithCloudModule(gcp.Module()).
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

## Recipe: long-running service with a shared policy

`Policy` is documented as safe for concurrent use and the per-check cost is
sub-microsecond, so a long-running service should build the policy **once at
process start** and share it across requests. The one-time setup is the only
indirection worth having — at call sites, use the `Policy` methods directly.

```go
package egress

import (
	"sync"

	"github.com/timescale/ressrf/go/ressrf-static"
	"github.com/timescale/ressrf/go/ressrf-static/cloud/aws" // only AWS — no Azure/GCP bytes in the binary
)

var (
	policyOnce sync.Once
	policy     *ressrfstatic.Policy
)

// Policy returns the lazily-built process-wide SSRF policy. Built once
// (~56 µs); the *Policy itself is safe for concurrent use after that.
// Bundles the IANA tiers via the ExternalOnly preset plus AWS
// metadata-endpoint denial via the aws sub-package.
func Policy() *ressrfstatic.Policy {
	policyOnce.Do(func() {
		p, err := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
			WithCloudModule(aws.Module()).
			Build()
		if err != nil {
			panic("egress: build policy: " + err.Error())
		}
		policy = p
	})
	return policy
}
```

That's the entire wrapper. Every consumer calls the `*Policy` methods
directly — no helper functions in between:

```go
// Pre-flight URL check (fail before pool.Begin / before issuing the HTTP request).
if err := egress.Policy().IsAllowed(ctx, rawURL); err != nil {
    return err // errors.Is(err, ressrfstatic.ErrBlocked) → true
}

// HTTP — drop the SSRF-safe DialContext straight into a cloned transport.
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.DialContext = egress.Policy().DialContext

// Or use the all-in-one client (sets transport + CheckRedirect):
client := egress.Policy().HTTPClient(nil)

// pgx
cfg, _ := pgx.ParseConfig(connStr)
cfg.DialFunc = egress.Policy().DialContext

// Kafka (segmentio)
dialer := kafka.Dialer{DialFunc: egress.Policy().DialContext}

// SSH
sshClient, err := egress.Policy().SSHDial(ctx, "host:22", sshConfig)
```

Two reasons this is faster than building per-request:
1. `Build()` is amortized to ~zero per request instead of paid 56 µs each time.
2. The `Control` hook inside `SafeDialer` / `DialContext` is the canonical
   security boundary (post-DNS, defeats rebinding). Pre-flight `net.LookupIP`
   wrappers that some codebases keep around are redundant — the dialer
   already does DNS once, and the `Control` hook validates whatever was
   resolved. Saves one lookup per request.

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

Apple M1 Max, Go 1.26, `-benchtime=5s` on both sides for equal sampling:

```
ressrf-static (native):
BenchmarkPolicyBuild         109004   55_911 ns/op   14_696 B/op   243 allocs/op
BenchmarkIsAllowed          4673055    1_287 ns/op      736 B/op    14 allocs/op
BenchmarkIsAllowedBlocked   8149558      815 ns/op      448 B/op     6 allocs/op
BenchmarkIsNetworkAllowed  12874878      481 ns/op      128 B/op     2 allocs/op

ressrf (WASM, same hardware, same benchtime):
BenchmarkPolicyBuild            720  7_793_066 ns/op  3_366_025 B/op   4_402 allocs/op
BenchmarkIsAllowed          2512359      2_399 ns/op        757 B/op      14 allocs/op
BenchmarkIsAllowedBlocked   1951185      3_078 ns/op        871 B/op      16 allocs/op
BenchmarkIsNetworkAllowed   3956259      1_508 ns/op        580 B/op      14 allocs/op
```

| Op | Native | WASM | Speedup |
|---|---:|---:|---:|
| `PolicyBuild` | 56 µs | 7.8 ms | ~140× |
| `IsAllowed` (allowed) | 1.29 µs | 2.40 µs | ~1.9× |
| `IsAllowed` (blocked) | 815 ns | 3.08 µs | ~3.8× |
| `IsNetworkAllowed` | 481 ns | 1.51 µs | ~3.1× |

Per-check operations are 2–4× faster. The big win is `PolicyBuild` (~140×):
the WASM-backed version pays for module instantiation each time. For
long-running services that build a policy once, this barely matters; for
short-lived CLIs or per-request policy construction, it's significant.

Reproduce with:

```
go test -bench=. -benchmem -run=^$ -benchtime=5s ./go/ressrf-static/...
go test -bench=. -benchmem -run=^$ -benchtime=5s ./go/ressrf/...
```

## Tree-shakable cloud providers

Each cloud provider lives in its own sub-package so the Go linker can prune
unused providers from the binary. The Azure dataset alone is ~3.1 MB.

```
go/ressrf-static/
├── cloud/
│   ├── aws/   (~440 KB)
│   ├── azure/ (~3.1 MB)
│   ├── gcp/   (~28 KB)
│   └── all/   (convenience: imports all three)
└── cloudmod/  (type definition only; no payload)
```

Import only the providers you need:

```go
import "github.com/timescale/ressrf/go/ressrf-static/cloud/aws"
b.WithCloudModule(aws.Module())
```

Measured impact: a minimal program importing only `cloud/aws` builds to a
6.7 MB binary; the same program with `cloud/all` is 9.9 MB. The extra 3.2 MB
is dead Azure + GCP data the linker would otherwise have to keep.

If you really want everything:

```go
import "github.com/timescale/ressrf/go/ressrf-static/cloud/all"
b.WithCloudModules(all.Modules()...)
```

## Caveats / non-goals

- **Cloud modules add deny CIDRs only**, matching WASM ABI behavior. For
  domain-level cloud denial, opt in via the provider sub-package's suffix
  accessors:
  ```go
  import "github.com/timescale/ressrf/go/ressrf-static/cloud/aws"
  b.WithCloudModule(aws.Module()).
    WithDeniedSuffixes(aws.DeniedSuffixes()...)
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
