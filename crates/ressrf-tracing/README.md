# ressrf-tracing

`TracingSink` adapter that bridges `ressrf-core` audit events to the `tracing` ecosystem. Emits structured `tracing::event!` calls with `ressrf.*` fields at configurable levels.

## Public API

| Type | Description |
|------|-------------|
| `TracingSink` | Implements `AuditSink`, emits tracing events |
| `AuditLevel` | Configures which tracing level to emit at (Trace, Debug, Info, Warn, Error) |

## Usage

```rust
use ressrf_core::PolicyBuilder;
use ressrf_tracing::{TracingSink, AuditLevel};

let sink = TracingSink::new(AuditLevel::Info);

let policy = PolicyBuilder::external_only()
    .audit_sink(Box::new(sink))
    .build();
```

Events appear as structured tracing spans/events with fields like `ressrf.event_type`, `ressrf.target`, `ressrf.decision`, enabling integration with any tracing subscriber (stdout, JSON, OpenTelemetry, etc.).

## License

MIT
