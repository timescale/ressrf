import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Policy } from "../src/policy.js";
import { resolveSafe, dnsLookup } from "../src/protocols/tcp.js";
import { RessrfBlockedError } from "../src/errors.js";

describe("TCP Protocol: resolveSafe", () => {
  it("blocks private IPs passed directly", async () => {
    const policy = await Policy.externalOnly();
    await assert.rejects(
      () => resolveSafe(policy, "10.0.0.1"),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("blocks loopback passed directly", async () => {
    const policy = await Policy.externalOnly();
    await assert.rejects(
      () => resolveSafe(policy, "127.0.0.1"),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("blocks IMDS IP passed directly", async () => {
    const policy = await Policy.externalOnly();
    await assert.rejects(
      () => resolveSafe(policy, "169.254.169.254"),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("allows public IPs passed directly", async () => {
    const policy = await Policy.externalOnly();
    const result = await resolveSafe(policy, "8.8.8.8");
    assert.deepStrictEqual(result, ["8.8.8.8"]);
    policy.close();
  });
});

describe("TCP Protocol: dnsLookup", () => {
  it("returns a function", async () => {
    const policy = await Policy.externalOnly();
    const lookup = dnsLookup(policy);
    assert.strictEqual(typeof lookup, "function");
    policy.close();
  });
});
