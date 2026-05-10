# ressrf-http

Tower Layer/Service for HTTP SSRF prevention. Validates request targets at the scheme, DNS resolution, and redirect levels. Integrates with any Tower-compatible HTTP stack (axum, tonic, reqwest, hyper).

## Features

- **SsrfLayer/SsrfService:** Tower middleware that validates scheme allowlists and literal-IP preflight checks before forwarding requests
- **Redirect validation:** per-hop re-validation of redirect targets against policy, with configurable max redirects
- **DNS-pinned connections:** pairs with `ressrf-tcp::SafeConnector` for resolve-time IP validation, preventing TOCTOU between DNS and connect

## Public API

| Type | Description |
|------|-------------|
| `SsrfLayer` | Tower `Layer` that wraps any inner service |
| `SsrfService<S>` | The wrapped service with scheme + IP validation |
| `RedirectPolicy` | Configuration for redirect following behavior |
| `RedirectValidator` | Per-request redirect chain state machine |
| `HttpGuardError` | Structured error (scheme, host blocked, redirect blocked, too many redirects) |

## Usage

```rust
use ressrf_core::PolicyBuilder;
use ressrf_http::{SsrfLayer, RedirectPolicy};

let policy = PolicyBuilder::external_only().build();
let layer = SsrfLayer::with_redirect_policy(
    policy,
    RedirectPolicy::follow(5),
);

// Apply to any Tower service stack
let svc = layer.layer(inner_http_service);
```

## License

MIT
