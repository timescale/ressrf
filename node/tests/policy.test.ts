import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Policy, PolicyBuilder } from "../src/policy.js";
import { RessrfBlockedError, isBlocked } from "../src/errors.js";

describe("Policy", () => {
  it("creates an external_only policy", async () => {
    const policy = await Policy.externalOnly();
    assert.ok(policy);
    policy.close();
  });

  it("creates an internal_only policy", async () => {
    const policy = await Policy.internalOnly();
    assert.ok(policy);
    policy.close();
  });

  it("external_only blocks private IPs", async () => {
    const policy = await Policy.externalOnly();
    assert.throws(
      () => policy.isNetworkAllowed(["10.0.0.1"]),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("external_only blocks loopback", async () => {
    const policy = await Policy.externalOnly();
    assert.throws(
      () => policy.isNetworkAllowed(["127.0.0.1"]),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("external_only blocks IMDS", async () => {
    const policy = await Policy.externalOnly();
    assert.throws(
      () => policy.isNetworkAllowed(["169.254.169.254"]),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("external_only allows public IPs", async () => {
    const policy = await Policy.externalOnly();
    assert.doesNotThrow(() => policy.isNetworkAllowed(["8.8.8.8"]));
    policy.close();
  });

  it("isAllowed blocks IMDS URL", async () => {
    const policy = await Policy.externalOnly();
    assert.throws(
      () => policy.isAllowed("http://169.254.169.254/latest/meta-data/"),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("isAllowed allows public URLs", async () => {
    const policy = await Policy.externalOnly();
    assert.doesNotThrow(() => policy.isAllowed("https://example.com/path"));
    policy.close();
  });

  it("isBlocked type guard works", async () => {
    const policy = await Policy.externalOnly();
    try {
      policy.isNetworkAllowed(["10.0.0.1"]);
      assert.fail("should have thrown");
    } catch (err) {
      assert.ok(isBlocked(err));
      assert.ok(err.reason.length > 0);
    }
    policy.close();
  });
});

describe("PolicyBuilder", () => {
  it("builds policy with denied CIDRs", async () => {
    const policy = await new PolicyBuilder("external_only")
      .addDenied("203.0.113.0/24")
      .build();

    assert.throws(
      () => policy.isNetworkAllowed(["203.0.113.5"]),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("builds policy with allowed CIDRs overriding deny", async () => {
    const policy = await new PolicyBuilder("external_only")
      .addAllowed("10.0.0.0/8")
      .build();

    assert.doesNotThrow(() => policy.isNetworkAllowed(["10.0.0.1"]));
    policy.close();
  });
});
