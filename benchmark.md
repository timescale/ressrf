# Benchmark Results

Environment: Apple M4 Pro, macOS, Rust 1.86.0, Go 1.25.5, wazero (interpreter)

## Rust (ressrf-core, native)

Tool: criterion 0.5

```
cidr_parse_v4                time:   [50.879 ns 51.213 ns 51.545 ns]
cidr_parse_v6                time:   [52.288 ns 52.459 ns 52.679 ns]
cidr_contains_hit            time:   [5.1075 ns 5.1409 ns 5.1954 ns]
cidr_contains_miss           time:   [4.5070 ns 4.5172 ns 4.5270 ns]
cidr_set_lookup_hit          time:   [11.416 ns 11.510 ns 11.685 ns]
cidr_set_lookup_miss         time:   [28.982 ns 29.109 ns 29.252 ns]
cidr_set_lookup_v6_hit       time:   [15.234 ns 15.351 ns 15.572 ns]
policy_build_external_only   time:   [2.8567 us 2.8642 us 2.8722 us]
policy_network_allowed       time:   [132.21 ns 133.78 ns 135.93 ns]
policy_network_blocked       time:   [42.152 ns 42.473 ns 42.997 ns]
uri_validate_allowed         time:   [223.21 ns 226.38 ns 230.84 ns]
uri_validate_bare_ip_blocked time:   [219.99 ns 221.36 ns 222.77 ns]
uri_validate_no_policy       time:   [224.46 ns 226.90 ns 230.15 ns]
```

| Operation | Latency | Notes |
|-----------|--------:|-------|
| CIDR parse (v4) | 51ns | Single string to struct |
| CIDR parse (v6) | 52ns | |
| CIDR contains (hit) | 5.1ns | Single IP vs single CIDR |
| CIDR contains (miss) | 4.5ns | |
| CidrSet lookup (hit, 9 entries) | 11.5ns | Linear scan, early exit |
| CidrSet lookup (miss, 9 entries) | 29ns | Full scan |
| CidrSet lookup (v6 hit) | 15ns | |
| Policy build (ExternalOnly) | 2.86us | Includes default deny set |
| Network check (allowed) | 134ns | Deny-set + allow-set scan |
| Network check (blocked) | 42ns | Early exit on first match |
| URI validate (allowed) | 226ns | Parse + scheme + host + policy |
| URI validate (blocked bare IP) | 221ns | |
| URI validate (no policy) | 227ns | Parse + scheme + host only |

## Go (ressrf, WASM via wazero interpreter)

Tool: `go test -bench`

```
BenchmarkPolicyBuild-12                      32    36653681 ns/op   11687868 B/op   20740 allocs/op
BenchmarkIsAllowed-12                   1000000        1081 ns/op        804 B/op      14 allocs/op
BenchmarkIsAllowedBlocked-12             760183        1570 ns/op        849 B/op      16 allocs/op
BenchmarkIsNetworkAllowed-12            1278217         937 ns/op        600 B/op      14 allocs/op
BenchmarkIsNetworkAllowedBlocked-12      908371        1253 ns/op        747 B/op      16 allocs/op
```

| Operation | Latency | Allocs | Notes |
|-----------|--------:|-------:|-------|
| Policy build | 37ms | 11.7MB / 20.7k | One-time (WASM compile + instantiate) |
| IsAllowed (allowed) | 1.1us | 804B / 14 | Per-request hot path |
| IsAllowed (blocked) | 1.6us | 850B / 16 | Includes error construction |
| IsNetworkAllowed (allowed) | 930ns | 600B / 14 | IP-only, no URL parsing |
| IsNetworkAllowed (blocked) | 1.3us | 740B / 16 | |

## Cross-platform comparison

| Operation | Rust native | Go (WASM) | Overhead |
|-----------|------------:|----------:|---------:|
| Policy build | 2.9us | 37ms | ~12,700x |
| Network check (allowed) | 134ns | 930ns | ~7x |
| Network check (blocked) | 42ns | 1,253ns | ~30x |
| URL validate (allowed) | 226ns | 1,081ns | ~5x |
| URL validate (blocked) | 221ns | 1,570ns | ~7x |

## Analysis

The WASM overhead on the hot path is 5-7x for the common "allowed" case. The absolute cost of ~1us per request is negligible compared to real network I/O (10-100ms for a typical HTTP call), adding roughly 0.001-0.01% to total request latency.

Policy construction (37ms) is a one-time startup cost. The WASM module is compiled and instantiated once, then the Policy handle is reused for the lifetime of the application.

### Cost breakdown per Go WASM call

1. JSON marshal of request (Go)
2. WASM linear memory alloc + write
3. Host-to-guest function call (wazero interpreter)
4. Validation logic (Rust compiled to WASM)
5. WASM linear memory read + dealloc
6. JSON unmarshal of result (Go)
7. Two mutex acquisitions (Policy + instance)

### Possible future optimizations

- Pre-compile WASM module once, share across policies (saves ~37ms per additional policy)
- Replace JSON FFI with length-prefixed binary protocol (fewer allocations per call)
- Use wazero compilation cache for faster cold starts after first run
- Use wazero compiler mode on supported platforms (2-5x hot-path speedup)
