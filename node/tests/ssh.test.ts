import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Policy } from "../src/policy.js";
import { RessrfBlockedError } from "../src/errors.js";
import { safeSshConnect } from "../src/protocols/ssh.js";

describe("safeSshConnect policy guards", () => {
  it("blocks private IP", async () => {
    const policy = await Policy.externalOnly();

    await assert.rejects(
      () =>
        safeSshConnect(policy, {
          host: "10.0.0.1",
          port: 22,
          timeout: 1000,
        }),
      (err: unknown) =>
        err instanceof RessrfBlockedError || err instanceof Error,
      "expected blocked for private IP SSH target",
    );

    policy.close();
  });

  it("blocks loopback", async () => {
    const policy = await Policy.externalOnly();

    await assert.rejects(
      () =>
        safeSshConnect(policy, {
          host: "127.0.0.1",
          port: 22,
          timeout: 1000,
        }),
      (err: unknown) =>
        err instanceof RessrfBlockedError || err instanceof Error,
      "expected blocked for loopback SSH target",
    );

    policy.close();
  });

  it("blocks IMDS", async () => {
    const policy = await Policy.externalOnly();

    await assert.rejects(
      () =>
        safeSshConnect(policy, {
          host: "169.254.169.254",
          port: 22,
          timeout: 1000,
        }),
      (err: unknown) =>
        err instanceof RessrfBlockedError || err instanceof Error,
      "expected blocked for IMDS SSH target",
    );

    policy.close();
  });
});
