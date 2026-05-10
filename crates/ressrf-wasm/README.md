# ressrf-wasm

Thin WASM ABI wrapper around `ressrf-core`. Compiles to `wasm32-wasip1` and exposes a C-style FFI for embedding in Go (via wazero) and Node.js (via WebAssembly API).

## Exported Functions

| Symbol | Description |
|--------|-------------|
| `ressrf_alloc(size) -> *mut u8` | Allocate guest memory for host writes |
| `ressrf_dealloc(ptr, size)` | Free allocated memory |
| `ressrf_policy_new(json_ptr, json_len) -> u32` | Create policy from JSON config, returns handle |
| `ressrf_policy_free(handle)` | Drop a policy instance |
| `ressrf_policy_is_network_allowed(handle, json_ptr, json_len) -> *mut u8` | Validate IPs |
| `ressrf_policy_is_request_allowed(handle, json_ptr, json_len) -> *mut u8` | Validate URL |
| `ressrf_uri_in_domain(json_ptr, json_len) -> *mut u8` | Check if URI matches domain list |
| `ressrf_policy_set_audit_callback(enabled)` | Enable/disable audit event callbacks |

## Host Import

The module expects a single host import:

```
env::ressrf_host_audit_event(ptr: i32, len: i32)
```

When audit is enabled, the guest calls this with a JSON-encoded `AuditEvent`.

## JSON Config (for `ressrf_policy_new`)

```json
{
  "preset": "external_only",
  "allow_cidrs": ["10.42.0.0/16"],
  "deny_cidrs": [],
  "cloud_providers": ["aws", "azure", "gcp"]
}
```

## Result Encoding

Results are returned as a pointer to: 4-byte little-endian length + JSON body.

```json
{"allowed": true}
{"allowed": false, "error": "blocked: IP in deny range 169.254.0.0/16"}
```

## Building

```bash
rustup target add wasm32-wasip1
cargo install wasm-tools
bash go/ressrf/build_wasm.sh
```

The build script compiles, runs `wasm-opt -Oz`, and strips with `wasm-tools strip`.

## License

MIT
