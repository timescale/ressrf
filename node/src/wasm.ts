import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = resolve(__dirname, "..", "core.wasm");

export interface WasmExports {
  memory: WebAssembly.Memory;
  ressrf_alloc(size: number): number;
  ressrf_dealloc(ptr: number, size: number): void;
  ressrf_policy_new(jsonPtr: number, jsonLen: number): number;
  ressrf_policy_free(handle: number): void;
  ressrf_policy_is_network_allowed(
    handle: number,
    jsonPtr: number,
    jsonLen: number,
  ): number;
  ressrf_policy_is_request_allowed(
    handle: number,
    jsonPtr: number,
    jsonLen: number,
  ): number;
  ressrf_uri_in_domain(jsonPtr: number, jsonLen: number): number;
  ressrf_policy_set_audit_callback(enabled: number): void;
}

export type AuditCallback = (event: Record<string, unknown>) => void;

export interface WasmResult {
  allowed: boolean;
  error?: string;
}

export class WasmInstance {
  private exports: WasmExports;
  private encoder = new TextEncoder();
  private decoder = new TextDecoder();

  constructor(exports: WasmExports) {
    this.exports = exports;
  }

  alloc(size: number): number {
    return this.exports.ressrf_alloc(size);
  }

  dealloc(ptr: number, size: number): void {
    this.exports.ressrf_dealloc(ptr, size);
  }

  writeJSON(data: unknown): { ptr: number; len: number } {
    const json = this.encoder.encode(JSON.stringify(data));
    const ptr = this.alloc(json.byteLength);
    if (ptr === 0) {
      throw new Error("ressrf: WASM alloc returned null");
    }
    const mem = new Uint8Array(this.exports.memory.buffer, ptr, json.byteLength);
    mem.set(json);
    return { ptr, len: json.byteLength };
  }

  readResult(ptr: number): WasmResult {
    const lenView = new DataView(this.exports.memory.buffer, ptr, 4);
    const len = lenView.getUint32(0, true);
    const jsonBytes = new Uint8Array(this.exports.memory.buffer, ptr + 4, len);
    const json = this.decoder.decode(jsonBytes.slice());
    this.dealloc(ptr, 4 + len);
    return JSON.parse(json) as WasmResult;
  }

  policyNew(jsonPtr: number, jsonLen: number): number {
    return this.exports.ressrf_policy_new(jsonPtr, jsonLen);
  }

  policyFree(handle: number): void {
    this.exports.ressrf_policy_free(handle);
  }

  policyIsNetworkAllowed(
    handle: number,
    jsonPtr: number,
    jsonLen: number,
  ): number {
    return this.exports.ressrf_policy_is_network_allowed(
      handle,
      jsonPtr,
      jsonLen,
    );
  }

  policyIsRequestAllowed(
    handle: number,
    jsonPtr: number,
    jsonLen: number,
  ): number {
    return this.exports.ressrf_policy_is_request_allowed(
      handle,
      jsonPtr,
      jsonLen,
    );
  }

  uriInDomain(jsonPtr: number, jsonLen: number): number {
    return this.exports.ressrf_uri_in_domain(jsonPtr, jsonLen);
  }

  setAuditCallback(enabled: boolean): void {
    this.exports.ressrf_policy_set_audit_callback(enabled ? 1 : 0);
  }
}

export interface LoadOptions {
  wasmPath?: string;
  auditCallback?: AuditCallback;
}

export async function loadWasm(options?: LoadOptions): Promise<WasmInstance> {
  const wasmPath = options?.wasmPath ?? WASM_PATH;
  const wasmBytes = readFileSync(wasmPath);

  let auditCallback = options?.auditCallback;
  const decoder = new TextDecoder();

  const importObject: WebAssembly.Imports = {
    wasi_snapshot_preview1: createWasiStub(),
    env: {
      ressrf_host_audit_event: (ptr: number, len: number) => {
        if (!auditCallback) return;
        const memory = (instance.exports as unknown as WasmExports).memory;
        const bytes = new Uint8Array(memory.buffer, ptr, len);
        const json = decoder.decode(bytes.slice());
        try {
          const event = JSON.parse(json) as Record<string, unknown>;
          auditCallback(event);
        } catch {
          // Silently drop malformed audit events
        }
      },
    },
  };

  const module = await WebAssembly.compile(wasmBytes);
  const instance = await WebAssembly.instantiate(module, importObject);
  const exports = instance.exports as unknown as WasmExports;

  return new WasmInstance(exports);
}

export function setAuditCallback(
  _instance: WasmInstance,
  callback: AuditCallback | undefined,
): void {
  // The callback is captured in the closure during loadWasm.
  // This function exists for API consistency but the actual binding
  // happens at load time via LoadOptions.auditCallback.
  _instance.setAuditCallback(callback != null);
}

function createWasiStub(): Record<string, (...args: number[]) => number> {
  const stub = () => 0;
  return {
    proc_exit: stub,
    fd_close: stub,
    fd_write: stub,
    fd_read: stub,
    fd_seek: stub,
    fd_prestat_get: () => 8, // EBADF
    fd_prestat_dir_name: stub,
    environ_get: stub,
    environ_sizes_get: stub,
    args_get: stub,
    args_sizes_get: stub,
    clock_time_get: stub,
    random_get: stub,
    path_open: stub,
    path_filestat_get: stub,
  };
}
