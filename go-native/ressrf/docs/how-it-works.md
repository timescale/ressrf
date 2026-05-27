# How ressrf works

*From a JSON spec to a blocked SSRF attempt, end to end.*

## Step 1 — The spec lives in JSON

*Source of truth.*

The deny-by-default ranges that protect every consumer of this library come from a small set of JSON files vendored from `timescale/ressrf`. They are the cross-language contract: the Rust core, the wazero binding, and this native Go port all consume the same bytes.

```jsonc
// config/ip_ranges.json (excerpt)
{
  "iana_ipv4_deny": [
    "0.0.0.0/8",        // This network (RFC791)
    "10.0.0.0/8",       // Private-Use (RFC1918)
    "127.0.0.0/8",      // Loopback (RFC1122)
    "169.254.0.0/16",   // Link-local (RFC3927); covers AWS IMDS
    "192.168.0.0/16",   // Private-Use (RFC1918)
    "...etc"
  ]
}
```

> The four `config/*.json` files plus the eight conformance vectors are the only data this port shares with upstream. The shared workspace path is `crates/ressrf-core/config/` and `tests/vectors/`; both bindings read the same files, so there is no per-PR drift check to maintain.

---

*Build time · `go generate ./...`*

## Step 2 — JSON becomes Go source

*Build-time codegen.*

The `internal/cmd/gen-data` tool reads `crates/ressrf-core/config/*.json` and emits two Go files into `internal/engine/`. It validates every CIDR through `engine.ParseCIDR` at build time (rejecting octal, hex, zone-ID, and other ambiguous forms), then emits `mustParseCIDR` calls so the runtime values are pre-parsed at package init.

```go
// internal/engine/ip_ranges_generated.go - DO NOT EDIT
package engine

var ianaIPv4Deny = [...]CIDR{
    mustParseCIDR("0.0.0.0/8", TierIana),
    mustParseCIDR("10.0.0.0/8", TierIana),
    mustParseCIDR("127.0.0.0/8", TierIana),
    mustParseCIDR("169.254.0.0/16", TierIana),
    mustParseCIDR("192.168.0.0/16", TierIana),
    // ... ~30 more entries ...
}
```

Pipeline: `crates/ressrf-core/config/ip_ranges.json` → `gen-data` (validates) → `ianaIPv4Deny []CIDR`.

---

*Package init (runs once before main).*

## Step 3 — What a CIDR carries

*The CIDR value.*

Each `mustParseCIDR` call materialises one `CIDR` struct with the prefix in canonical (masked) form, the original string for audit output, and a `DataTier` tag identifying which list the entry came from. The whole array is built before `main()` runs.

```go
type CIDR struct {
    Prefix   netip.Prefix  // canonical, masked, zero-alloc Contains()
    Original string        // "169.254.0.0/16"; preserved for audit
    Source   DataTier      // TierIana / TierUserDeny / TierCspMetadata
}
```

When `NewPolicy(PresetExternalOnly)` runs, it copies the pre-built array into `policy.denySet.Ranges`. The slice is scanned linearly on every check; for ~30 entries that beats a tree structure on cache locality.

---

*Caller-facing API.*

## Step 4 — Create a policy

*Caller code.*

The user composes a `Policy` with functional options. The preset seeds the deny set with the IANA + cloud-metadata ranges from steps 1–3; options layer per-app rules on top.

```go
import (
    "github.com/timescale/ressrf/go-native/ressrf"
    "github.com/timescale/ressrf/go-native/ressrf/httpx"
)

policy, err := ressrf.NewPolicy(ressrf.PresetExternalOnly,
    ressrf.WithCloudProviderDenies(ressrf.CloudAWS, ressrf.CloudAzure, ressrf.CloudGCP),
    ressrf.WithAllowedCIDRs("10.42.0.0/16"),
)
```

After this call, the `*Policy` holds an immutable, concurrency-safe view of every CIDR you must not connect to.

---

*Wrapping the HTTP stack.*

## Step 5 — Create a protected HTTP client

*Wrapping http.Client.*

`httpx.Client` returns an `*http.Client` that wires the policy into *three* checkpoints. Skipping any one of them is the bug attackers exploit.

```go
client := httpx.Client(policy)
```

What that single line installs:

- **RoundTrip hook**: runs `policy.IsAllowed(url)` before any bytes leave the process. Catches obviously-bad URLs (bare internal IPs, encoded-IP tricks, cloud-metadata FQDNs).
- **Dialer Control hook**: runs `policy.IsNetworkAllowed(ip)` after DNS resolves but before `connect()`. Catches "`evil.com` resolved to `10.0.0.5`", where the URL string was fine but the resolved IP wasn't.
- **CheckRedirect**: re-runs both checks on every 3xx hop. Catches `http://public/start` → `302 Location: http://10.0.0.5/admin`.

---

*A request fires.*

## Step 6 — A spoofy URL hits the client

*Adversarial request.*

Caller code asks for the AWS instance-metadata endpoint, the classic SSRF payload that returns IAM role credentials on an unprotected EC2 host.

```go
resp, err := client.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
```

The request never reaches the network. Inside the wrapped transport:

```go
// internal/engine/uri_validator.go (simplified)
func (v *URIValidator) validateURL(rawURL string, p *Policy) DenyReason {
    parts, _ := parseURLParts(rawURL)            // scheme + host + port
    if IsAmbiguousIP(parts.host) { ... }         // BS-1: octal/hex/decimal; not this case
    if IsIPLiteral(parts.host) {                 // 169.254.169.254 IS a bare IP literal
        ip, _ := parseHostAsIP(parts.host)
        if reason := p.isNetworkAllowedIPs([]netip.Addr{ip}); reason != nil {
            // scan denySet → matches 169.254.0.0/16 from ip_ranges.json
            return &BareIPDeniedBeforeScheme{Host: ip.String()}
        }
    }
    ...
}
```

## Step 7 — The error the caller gets back

*Result.*

The block surfaces as an `error` the caller can inspect structurally. No connection was opened; no DNS lookup hit the wire; no metadata token was leaked.

```go
resp, err := client.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
if err != nil {
    var be *ressrf.BlockedError
    if errors.As(err, &be) {
        switch r := be.Reason.(type) {
        case *ressrf.BareIPDeniedBeforeScheme:
            // r.Host == "169.254.169.254"
            log.Warn("blocked SSRF attempt", "host", r.Host)
        case *ressrf.InDenyCIDR:
            log.Warn("blocked CIDR", "cidr", r.CIDR, "source", r.Source)
        }
    }
}
```

> `err` is an `*ressrf.BlockedError` whose `Reason` is `*BareIPDeniedBeforeScheme{Host: "169.254.169.254"}`. `errors.Is(err, ressrf.ErrBlocked)` returns true for callers who only care that *something* was blocked. The audit sink (if attached) also receives a `url_validated` event with `allowed=false` and `deny_kind="bare_ip_denied_before_scheme"`.

## End to end

*The whole pipeline at a glance.*

`config/ip_ranges.json` → `gen-data` (validates) → `ianaIPv4Deny []CIDR` (pre-parsed at init) → `policy.denySet` → `policy.IsAllowed(url)` → `BareIPDeniedBeforeScheme` → `*BlockedError`

The same JSON drives every other binding, so all of them refuse the same attack.

---

Companion to the ressrf README. See `example_test.go` for runnable Go examples and `internal/diff/` for the differential-fuzz harness that keeps this port in sync with the Rust core.
