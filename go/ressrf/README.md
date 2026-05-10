# ressrf (Go)

Go package for SSRF prevention, powered by the `ressrf-core` engine running in a WASM sandbox via [wazero](https://wazero.io). Zero CGO, zero network dependencies at runtime. The WASM binary is embedded via `//go:embed`.

## Installation

```bash
go get github.com/mostafa/ressrf/go/ressrf
```

Requires Go 1.22+.

## Public API

### PolicyBuilder

| Method | Description |
|--------|-------------|
| `NewPolicyBuilder(preset Preset) *PolicyBuilder` | Create a builder starting from a preset |
| `WithAllowedCIDRs(cidrs ...string) *PolicyBuilder` | Add CIDRs to the allow list (overrides deny) |
| `WithDeniedCIDRs(cidrs ...string) *PolicyBuilder` | Add CIDRs to the deny list |
| `WithCloudProviders(providers ...string) *PolicyBuilder` | Enable cloud metadata protection (`"aws"`, `"azure"`, `"gcp"`) |
| `WithURLAllow(rule URLRule) *PolicyBuilder` | Add a URL allow rule (glob/regex pattern) |
| `WithURLDeny(rule URLRule) *PolicyBuilder` | Add a URL deny rule (glob/regex pattern) |
| `WithAuditSink(sink AuditSink) *PolicyBuilder` | Attach an audit event listener |
| `Build(ctx context.Context) (*Policy, error)` | Compile and return the policy |

### Presets

| Constant | Description |
|----------|-------------|
| `PresetExternalOnly` | Default deny for private/internal ranges; allow public internet |
| `PresetInternalOnly` | Default deny all; only explicitly allowed CIDRs pass |
| `PresetNone` | No blocking; audit-only mode |

### Policy

| Method | Description |
|--------|-------------|
| `IsAllowed(ctx, url string) error` | Validate a URL (scheme + host + IP check) |
| `IsNetworkAllowed(ctx, ips []string) error` | Validate raw IP addresses against the policy |
| `Close(ctx) error` | Release WASM instance resources |

The `Policy` is safe for concurrent use (internally mutex-protected).

### Protocol Adapters

#### HTTP

| Method | Description |
|--------|-------------|
| `HTTPTransport(base http.RoundTripper) http.RoundTripper` | Returns a transport with DNS validation and redirect re-validation. Wraps the base transport (or `http.DefaultTransport` if nil), preserving proxy settings, TLS config, and connection pooling. |
| `HTTPClient(base http.RoundTripper) *http.Client` | Returns a complete `*http.Client` with SSRF-safe transport and redirect checking |

The HTTP transport provides two layers of protection:

1. **Pre-request validation:** the `RoundTripper` calls `IsAllowed` on the request URL before forwarding
2. **Control hook:** the underlying `net.Dialer.Control` re-validates resolved IPs at socket time (prevents DNS rebinding)
3. **Redirect re-validation:** `CheckRedirect` validates each redirect target, blocks HTTPS-to-HTTP downgrades, and caps at 10 hops

```go
// Use with a custom base transport
customTransport := &http.Transport{
    MaxIdleConns:    100,
    IdleConnTimeout: 90 * time.Second,
}
client := policy.HTTPClient(customTransport)
resp, err := client.Get("https://api.example.com/data")

// Or get just the transport for your own http.Client
transport := policy.HTTPTransport(nil) // wraps http.DefaultTransport
client := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}
```

#### TCP

| Method | Description |
|--------|-------------|
| `SafeDialer() *net.Dialer` | Returns a dialer with a `Control` hook that validates resolved IPs (30s default timeout) |
| `SafeDialerWithTimeout(timeout time.Duration) *net.Dialer` | Same as `SafeDialer` with a custom timeout |
| `DialContext(ctx, network, address string) (net.Conn, error)` | Convenience method: dials after validating against the policy |

The `Control` hook runs after DNS resolution but before the TCP handshake, validating the resolved IP. This eliminates DNS rebinding attacks.

```go
// Use as a drop-in DialContext replacement
transport := &http.Transport{
    DialContext: policy.DialContext,
}

// Or get the dialer for lower-level use
dialer := policy.SafeDialerWithTimeout(10 * time.Second)
conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
```

#### SSH

| Method | Description |
|--------|-------------|
| `SSHDial(ctx, addr string, config *ssh.ClientConfig) (*ssh.Client, error)` | SSH dial over policy-validated TCP |

Validates the target address, dials via `SafeDialer`, performs the SSH handshake with a deadline, then clears the deadline for normal operation.

```go
import "golang.org/x/crypto/ssh"

config := &ssh.ClientConfig{
    User:            "deploy",
    Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    Timeout:         10 * time.Second,
}

client, err := policy.SSHDial(ctx, "git.example.com:22", config)
if err != nil {
    if errors.Is(err, ressrf.ErrBlocked) {
        log.Println("SSH target is blocked by policy")
    }
    return err
}
defer client.Close()
```

### Audit Logging

| Type | Description |
|------|-------------|
| `AuditSink` | Interface: `Emit(ctx context.Context, event *AuditEvent)` |
| `AuditFunc` | Adapter: any `func(context.Context, *AuditEvent)` satisfies `AuditSink` |
| `MultiSink` | Fans out events to multiple sinks |
| `DiscardSink` | Silently drops all events |

```go
// AuditEvent structure
type AuditEvent struct {
    Kind      string          `json:"kind"`
    Timestamp time.Time       `json:"timestamp,omitempty"`
    Fields    json.RawMessage `json:"fields,omitempty"`
}
```

Events are emitted from the WASM guest via a host-imported function (`ressrf_host_audit_event`). The JSON is parsed into `AuditEvent` and dispatched to the configured sink.

```go
// With slog
sink := ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
    slog.InfoContext(ctx, "ressrf.audit",
        "kind", e.Kind,
        "fields", string(e.Fields),
    )
})

// With zap
sink := ressrf.AuditFunc(func(_ context.Context, e *ressrf.AuditEvent) {
    logger.Info("ressrf.audit",
        zap.String("kind", e.Kind),
        zap.String("fields", string(e.Fields)),
    )
})

// Multiple sinks
sink := ressrf.MultiSink{slogSink, metricsSink}

policy, _ := ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
    WithAuditSink(sink).
    Build(ctx)
```

### URL Rules

URL-level allow/deny with glob patterns and optional regex. Deny rules are evaluated first. When allow rules are configured, URLs not matching any are blocked.

```go
policy, _ := ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
    WithURLAllow(ressrf.URLRule{Scheme: "https", Host: "*.stripe.com", Path: "/v1/**"}).
    WithURLAllow(ressrf.URLRule{Host: "internal-api.company.com", BypassIPCheck: true}).
    WithURLDeny(ressrf.URLRule{Host: "*.internal"}).
    WithURLDeny(ressrf.URLRule{Regex: `^http://.*$`}).
    Build(ctx)
```

| Field | Type | Description |
|-------|------|-------------|
| `Scheme` | `string` | Exact scheme match (empty = any) |
| `Host` | `string` | Host glob (`*` = single DNS label) |
| `Path` | `string` | Path glob (`*` = one segment, `**` = any depth) |
| `Regex` | `string` | Full URL regex (overrides Scheme/Host/Path) |
| `BypassIPCheck` | `bool` | When true on allow rule, skip IP-level validation |

### Error Handling

| Type | Description |
|------|-------------|
| `ErrBlocked` | Sentinel error for policy rejections |
| `BlockedError` | Wraps `ErrBlocked` with `.Reason` and `.URL` fields |

```go
err := policy.IsAllowed(ctx, url)
if errors.Is(err, ressrf.ErrBlocked) {
    var blocked *ressrf.BlockedError
    if errors.As(err, &blocked) {
        log.Printf("blocked: reason=%s url=%s", blocked.Reason, blocked.URL)
    }
}
```

### Testing

| Function | Description |
|----------|-------------|
| `Disabled() bool` | Returns true when protection is disabled |
| `DisableForTests(t testing.TB)` | Disables protection for the duration of `t`, auto-restores via `t.Cleanup` |

```go
func TestMyHandler(t *testing.T) {
    ressrf.DisableForTests(t) // all policy checks become no-ops

    // Test code that needs to reach loopback infrastructure
    resp, err := client.Get("http://127.0.0.1:8080/health")
    // ...
}
// Protection is automatically re-enabled after the test
```

## Complete Example

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "io"
    "log/slog"
    "net/http"

    "github.com/mostafa/ressrf/go/ressrf"
)

func main() {
    ctx := context.Background()

    // Build a policy with cloud protection and audit logging
    policy, err := ressrf.NewPolicyBuilder(ressrf.PresetExternalOnly).
        WithCloudProviders("aws", "azure", "gcp").
        WithAllowedCIDRs("10.42.0.0/16"). // internal k8s services
        WithAuditSink(ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
            slog.InfoContext(ctx, "ressrf", "kind", e.Kind)
        })).
        Build(ctx)
    if err != nil {
        panic(err)
    }
    defer policy.Close(ctx)

    // Get an SSRF-safe HTTP client
    client := policy.HTTPClient(nil)

    // Public URLs work
    resp, err := client.Get("https://api.example.com/data")
    if err == nil {
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()
        fmt.Println("Public request succeeded:", resp.Status)
    }

    // IMDS is blocked
    _, err = client.Get("http://169.254.169.254/latest/meta-data/")
    if errors.Is(err, ressrf.ErrBlocked) {
        fmt.Println("IMDS blocked as expected")
    }

    // Private IPs are blocked (except allow-listed range)
    err = policy.IsNetworkAllowed(ctx, []string{"10.0.0.1"})
    fmt.Println("10.0.0.1:", err) // blocked

    err = policy.IsNetworkAllowed(ctx, []string{"10.42.1.5"})
    fmt.Println("10.42.1.5:", err) // allowed (in 10.42.0.0/16)
}
```

## Constants

| Name | Value | Description |
|------|-------|-------------|
| `defaultDialTimeout` | 30s | Default TCP dial timeout for `SafeDialer` and `DialContext` |
| Max redirects | 10 | Maximum redirect hops before `CheckRedirect` returns an error |

## Architecture

The package embeds `core.wasm` (the compiled `ressrf-wasm` crate) and loads it into a wazero runtime at `Build()` time. Each `Policy` instance owns a WASM module instance with its own linear memory. The host registers a single import function (`env.ressrf_host_audit_event`) to receive audit event callbacks from the guest.

All WASM interactions are mutex-protected, making the `Policy` safe for concurrent use from multiple goroutines.

## License

MIT
