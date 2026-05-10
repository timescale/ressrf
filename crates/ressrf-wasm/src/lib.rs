//! WASM ABI wrapper for `ressrf-core`.
//!
//! Exposes core policy and validation functions through a C-ABI-compatible
//! interface for consumption by Go (wazero) and Node.js (WebAssembly).
//! Data passes as JSON strings via linear memory.
//!
//! # Exported Functions
//!
//! - `ressrf_alloc(size) -> ptr` -- allocate memory for host-to-guest data transfer
//! - `ressrf_dealloc(ptr, size)` -- free memory allocated by `ressrf_alloc`
//! - `ressrf_policy_new(json_ptr, json_len) -> handle` -- create a policy from JSON config
//! - `ressrf_policy_free(handle)` -- destroy a policy
//! - `ressrf_policy_is_network_allowed(handle, json_ptr, json_len) -> result_ptr`
//! - `ressrf_policy_is_request_allowed(handle, json_ptr, json_len) -> result_ptr`
//! - `ressrf_uri_in_domain(uri_ptr, uri_len, domains_ptr, domains_len) -> result_ptr`
//!
//! All result pointers point to a JSON string in linear memory that the host
//! must read and then free with `ressrf_dealloc`.

#![no_std]
// WASM FFI requires raw pointer manipulation and no_mangle exports.
// The cast_possible_truncation warnings are false positives: this crate
// targets wasm32 where usize == u32.
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::cast_possible_truncation,
    clippy::too_long_first_doc_paragraph
)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::slice;

use ressrf_core::{CloudProvider, PolicyBuilder, Preset, UrlRuleset};
use serde::{Deserialize, Serialize};

/// Opaque handle to a Policy instance stored on the heap.
type PolicyHandle = u32;

/// Global policy storage. In WASM single-threaded execution, this is safe.
static mut POLICIES: Vec<Option<ressrf_core::Policy>> = Vec::new();

fn store_policy(policy: ressrf_core::Policy) -> PolicyHandle {
    // Safety: WASM is single-threaded
    #[allow(static_mut_refs)]
    let policies = unsafe { &mut POLICIES };
    let handle = policies.len() as PolicyHandle;
    policies.push(Some(policy));
    handle
}

fn get_policy(handle: PolicyHandle) -> Option<&'static ressrf_core::Policy> {
    // Safety: WASM is single-threaded
    #[allow(static_mut_refs)]
    let policies = unsafe { &POLICIES };
    policies.get(handle as usize).and_then(|p| p.as_ref())
}

fn remove_policy(handle: PolicyHandle) {
    // Safety: WASM is single-threaded
    #[allow(static_mut_refs)]
    let policies = unsafe { &mut POLICIES };
    if let Some(slot) = policies.get_mut(handle as usize) {
        *slot = None;
    }
}

/// Input format for creating a policy.
#[derive(Deserialize)]
struct PolicyConfig {
    preset: String,
    #[serde(default)]
    allow_cidrs: Vec<String>,
    #[serde(default)]
    deny_cidrs: Vec<String>,
    #[serde(default)]
    cloud_providers: Vec<String>,
    #[serde(default)]
    url_rules: Option<UrlRuleset>,
}

/// Input format for network validation.
#[derive(Deserialize)]
struct NetworkCheckInput {
    ips: Vec<String>,
}

/// Input format for request validation.
#[derive(Deserialize)]
struct RequestCheckInput {
    url: String,
}

/// Input format for domain check.
#[derive(Deserialize)]
struct DomainCheckInput {
    uri: String,
    domains: Vec<String>,
}

/// Standard result format returned to the host.
#[derive(Serialize)]
struct WasmResult {
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Allocate `size` bytes in WASM linear memory. Returns a pointer the host
/// can write to before calling other exported functions.
/// Returns null if size is 0.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_alloc(size: u32) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let layout = alloc::alloc::Layout::from_size_align(size as usize, 1).unwrap();
    // Safety: layout has non-zero size
    unsafe { alloc::alloc::alloc(layout) }
}

/// Deallocate memory previously allocated by `ressrf_alloc`.
/// No-op if ptr is null or size is 0.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_dealloc(ptr: *mut u8, size: u32) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let layout = alloc::alloc::Layout::from_size_align(size as usize, 1).unwrap();
    // Safety: ptr was allocated by ressrf_alloc with this layout
    unsafe { alloc::alloc::dealloc(ptr, layout) };
}

/// Create a new policy from a JSON configuration string.
/// Returns a handle (u32) that can be used with other functions.
/// Returns `u32::MAX` on error.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_policy_new(json_ptr: *const u8, json_len: u32) -> PolicyHandle {
    let json_bytes = unsafe { slice::from_raw_parts(json_ptr, json_len as usize) };
    let config: PolicyConfig = match serde_json::from_slice(json_bytes) {
        Ok(c) => c,
        Err(_) => return u32::MAX,
    };

    let preset = match config.preset.as_str() {
        "internal_only" => Preset::InternalOnly,
        "external_only" => Preset::ExternalOnly,
        "none" => Preset::None,
        _ => return u32::MAX,
    };

    let mut builder = PolicyBuilder::new(preset);

    let allow_refs: Vec<&str> = config.allow_cidrs.iter().map(String::as_str).collect();
    if !allow_refs.is_empty() {
        builder.add_allowed(&allow_refs);
    }

    let deny_refs: Vec<&str> = config.deny_cidrs.iter().map(String::as_str).collect();
    if !deny_refs.is_empty() {
        builder.add_denied(&deny_refs);
    }

    for name in &config.cloud_providers {
        match name.as_str() {
            "aws" => {
                builder.with_cloud(CloudProvider::Aws);
            }
            "azure" => {
                builder.with_cloud(CloudProvider::Azure);
            }
            "gcp" => {
                builder.with_cloud(CloudProvider::Gcp);
            }
            _ => {}
        }
    }

    if let Some(url_rules) = config.url_rules {
        builder.url_ruleset(url_rules);
    }

    #[allow(static_mut_refs)]
    let audit_enabled = unsafe { AUDIT_ENABLED };
    if audit_enabled {
        builder.audit_sink(alloc::boxed::Box::new(WasmAuditSink));
    }

    let policy = builder.build();
    store_policy(policy)
}

/// Free a policy by handle.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_policy_free(handle: PolicyHandle) {
    remove_policy(handle);
}

/// Check if a set of IPs is allowed by the policy.
/// Input: JSON `{"ips": ["1.2.3.4", "::1"]}`.
/// Returns a pointer to a JSON result string. The host must read and then free it.
/// The first 4 bytes at the returned pointer encode the length as little-endian u32.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_policy_is_network_allowed(
    handle: PolicyHandle,
    json_ptr: *const u8,
    json_len: u32,
) -> *mut u8 {
    let result = (|| {
        let policy = get_policy(handle).ok_or("invalid policy handle")?;
        let json_bytes = unsafe { slice::from_raw_parts(json_ptr, json_len as usize) };
        let input: NetworkCheckInput =
            serde_json::from_slice(json_bytes).map_err(|e| alloc::format!("parse error: {e}"))?;

        let ips: Vec<core::net::IpAddr> = input
            .ips
            .iter()
            .map(|s| s.parse().map_err(|e| alloc::format!("invalid IP {s}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        match policy.is_network_allowed(&ips) {
            Ok(()) => Ok(WasmResult {
                allowed: true,
                error: None,
            }),
            Err(e) => Ok(WasmResult {
                allowed: false,
                error: Some(alloc::format!("{e}")),
            }),
        }
    })();

    let wasm_result = match result {
        Ok(r) => r,
        Err(e) => WasmResult {
            allowed: false,
            error: Some(e),
        },
    };

    serialize_result(&wasm_result)
}

/// Check if a URL request is allowed by the policy.
/// Input: JSON `{"url": "http://example.com/path"}`.
/// Returns a pointer to a length-prefixed JSON result string.
///
/// Evaluation order:
/// 1. URL rules (deny first, then allow with optional `bypass_ip_check`)
/// 2. URI structural validation (scheme, userinfo, domain suffixes)
/// 3. IP-level network check (if URL rule did not bypass)
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_policy_is_request_allowed(
    handle: PolicyHandle,
    json_ptr: *const u8,
    json_len: u32,
) -> *mut u8 {
    let result = (|| {
        let policy = get_policy(handle).ok_or("invalid policy handle")?;
        let json_bytes = unsafe { slice::from_raw_parts(json_ptr, json_len as usize) };
        let input: RequestCheckInput =
            serde_json::from_slice(json_bytes).map_err(|e| alloc::format!("parse error: {e}"))?;

        // Check URL rules first
        match policy.validate_url_rules(&input.url) {
            Err(e) => {
                return Ok(WasmResult {
                    allowed: false,
                    error: Some(alloc::format!("{e}")),
                });
            }
            Ok(bypass_ip) => {
                if bypass_ip {
                    return Ok(WasmResult {
                        allowed: true,
                        error: None,
                    });
                }
            }
        }

        let validator = ressrf_core::UriValidator::default();
        match validator.validate_url(&input.url, Some(policy)) {
            Ok(()) => Ok(WasmResult {
                allowed: true,
                error: None,
            }),
            Err(e) => Ok(WasmResult {
                allowed: false,
                error: Some(alloc::format!("{e}")),
            }),
        }
    })();

    let wasm_result = match result {
        Ok(r) => r,
        Err(e) => WasmResult {
            allowed: false,
            error: Some(e),
        },
    };

    serialize_result(&wasm_result)
}

/// Check if a URI belongs to one of the given domain suffixes.
/// Input: JSON `{"uri": "https://api.example.com/v1", "domains": [".example.com"]}`.
/// Returns a pointer to a length-prefixed JSON result string.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_uri_in_domain(json_ptr: *const u8, json_len: u32) -> *mut u8 {
    let result = (|| {
        let json_bytes = unsafe { slice::from_raw_parts(json_ptr, json_len as usize) };
        let input: DomainCheckInput =
            serde_json::from_slice(json_bytes).map_err(|e| alloc::format!("parse error: {e}"))?;

        let domain_refs: Vec<&str> = input.domains.iter().map(String::as_str).collect();
        let mut validator = ressrf_core::UriValidator::new();
        validator.add_trusted_suffixes(&domain_refs);

        match validator.validate_url(&input.uri, None) {
            Ok(()) => Ok(WasmResult {
                allowed: true,
                error: None,
            }),
            Err(e) => Ok(WasmResult {
                allowed: false,
                error: Some(alloc::format!("{e}")),
            }),
        }
    })();

    let wasm_result = match result {
        Ok(r) => r,
        Err(e) => WasmResult {
            allowed: false,
            error: Some(e),
        },
    };

    serialize_result(&wasm_result)
}

// --- Audit callback support ---

#[cfg(target_arch = "wasm32")]
extern "C" {
    /// Host-provided function called when an audit event is emitted.
    /// The guest writes a length-prefixed JSON string to linear memory and
    /// passes the pointer and total length. The host reads and frees it.
    fn ressrf_host_audit_event(ptr: *const u8, len: u32);
}

#[cfg(not(target_arch = "wasm32"))]
unsafe extern "C" fn ressrf_host_audit_event(_ptr: *const u8, _len: u32) {}

/// Global flag: whether audit callbacks are enabled.
static mut AUDIT_ENABLED: bool = false;

/// Enable audit event callbacks. After calling this, newly created policies
/// will have a `WasmAuditSink` attached that calls the host-imported
/// `ressrf_host_audit_event` function with JSON-serialized events.
#[unsafe(no_mangle)]
pub extern "C" fn ressrf_policy_set_audit_callback(enabled: u32) {
    #[allow(static_mut_refs)]
    unsafe {
        AUDIT_ENABLED = enabled != 0;
    }
}

/// Audit sink that calls the host-imported function.
struct WasmAuditSink;

impl ressrf_core::AuditSink for WasmAuditSink {
    fn emit(&self, event: &ressrf_core::audit::AuditEvent) {
        let Ok(json) = serde_json::to_vec(event) else {
            return;
        };
        unsafe {
            ressrf_host_audit_event(json.as_ptr(), json.len() as u32);
        }
    }
}

/// Serialize a result to a length-prefixed buffer in linear memory.
/// Layout: [u32 LE length][JSON bytes]
/// The host reads the first 4 bytes as length, then reads that many bytes.
/// The entire allocation (4 + len) must be freed with `ressrf_dealloc`.
fn serialize_result(result: &WasmResult) -> *mut u8 {
    let json = serde_json::to_vec(result).unwrap_or_else(|_| b"{}".to_vec());
    let total_len = 4 + json.len();
    let ptr = ressrf_alloc(total_len as u32);
    // Safety: ptr is freshly allocated with sufficient size
    unsafe {
        let len_bytes = (json.len() as u32).to_le_bytes();
        core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), ptr, 4);
        core::ptr::copy_nonoverlapping(json.as_ptr(), ptr.add(4), json.len());
    }
    ptr
}
