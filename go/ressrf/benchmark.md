# Benchmark Results

Environment: Apple M4 Pro, macOS, Go 1.25.5, wazero (interpreter)

```
goos: darwin
goarch: arm64
pkg: github.com/mostafa/ressrf/go/ressrf
cpu: Apple M4 Pro
BenchmarkPolicyBuild-12                      32    36653681 ns/op   11687868 B/op   20740 allocs/op
BenchmarkIsAllowed-12                   1000000        1081 ns/op        804 B/op      14 allocs/op
BenchmarkIsAllowedBlocked-12             760183        1570 ns/op        849 B/op      16 allocs/op
BenchmarkIsNetworkAllowed-12            1278217         937 ns/op        600 B/op      14 allocs/op
BenchmarkIsNetworkAllowedBlocked-12      908371        1253 ns/op        747 B/op      16 allocs/op
```

## Summary

| Operation | Latency | Allocations | Notes |
|-----------|---------|-------------|-------|
| `PolicyBuilder.Build` | ~37ms | 11.7MB / 20.7k allocs | One-time startup cost (WASM compile + instantiate) |
| `IsAllowed` (allowed) | ~1.1us | 804B / 14 allocs | Per-request hot path |
| `IsAllowed` (blocked) | ~1.6us | 850B / 16 allocs | Includes error construction |
| `IsNetworkAllowed` (allowed) | ~930ns | 600B / 14 allocs | IP-only, no URL parsing |
| `IsNetworkAllowed` (blocked) | ~1.3us | 740B / 16 allocs | |

## Overhead in context

A typical HTTP round-trip to an external service takes 10-100ms.
The per-request SSRF validation adds ~1us, which is 0.001-0.01% of total request latency.

## Cost breakdown per call

1. JSON marshal of request (Go side)
2. WASM linear memory allocation + write
3. Host-to-guest function call (wazero interpreter)
4. Validation logic (Rust, compiled to WASM)
5. WASM linear memory read + dealloc
6. JSON unmarshal of result (Go side)
7. Two mutex acquisitions (Policy + instance)

## Possible future optimizations

- Pre-compile the WASM module once and share across policies (saves ~37ms per additional policy)
- Switch JSON serialization to a length-prefixed binary protocol (reduces per-call allocations)
- Use wazero's compilation cache to persist compiled code to disk (faster cold starts)
- Use wazero's compiler mode instead of interpreter on supported platforms (2-5x speedup on hot path)
