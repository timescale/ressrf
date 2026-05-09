import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadWasm } from "../src/wasm.js";

describe("WasmInstance", () => {
  it("loads WASM module successfully", async () => {
    const wasm = await loadWasm();
    assert.ok(wasm, "loadWasm should return a WasmInstance");
  });

  it("alloc and dealloc work without crashing", async () => {
    const wasm = await loadWasm();
    const ptr = wasm.alloc(64);
    assert.ok(ptr > 0, "alloc should return non-zero pointer");
    wasm.dealloc(ptr, 64);
  });

  it("alloc of zero returns null pointer", async () => {
    const wasm = await loadWasm();
    const ptr = wasm.alloc(0);
    assert.strictEqual(ptr, 0);
  });

  it("writeJSON produces valid pointer and length", async () => {
    const wasm = await loadWasm();
    const { ptr, len } = wasm.writeJSON({ hello: "world" });
    assert.ok(ptr > 0);
    assert.ok(len > 0);
    wasm.dealloc(ptr, len);
  });

  it("policyNew returns a valid handle for external_only", async () => {
    const wasm = await loadWasm();
    const { ptr, len } = wasm.writeJSON({
      preset: "external_only",
      allow_cidrs: [],
      deny_cidrs: [],
    });
    const handle = wasm.policyNew(ptr, len);
    assert.notStrictEqual(handle, 0xffffffff, "handle should not be error sentinel");
    wasm.policyFree(handle);
  });

  it("policyNew returns error for invalid preset", async () => {
    const wasm = await loadWasm();
    const { ptr, len } = wasm.writeJSON({
      preset: "invalid_preset",
      allow_cidrs: [],
      deny_cidrs: [],
    });
    const handle = wasm.policyNew(ptr, len);
    // WASM returns u32::MAX (0xFFFFFFFF) which JS may interpret as -1 (signed i32)
    assert.ok(handle === 0xffffffff || handle === -1);
  });
});
