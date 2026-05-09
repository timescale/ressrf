import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Policy } from "../src/policy.js";
import { httpAgent, httpsAgent, validateRedirect } from "../src/protocols/http.js";
import { RessrfBlockedError } from "../src/errors.js";

describe("HTTP Protocol: httpAgent", () => {
  it("creates an http.Agent", async () => {
    const policy = await Policy.externalOnly();
    const agent = httpAgent(policy);
    assert.ok(agent);
    policy.close();
  });
});

describe("HTTP Protocol: httpsAgent", () => {
  it("creates an https.Agent", async () => {
    const policy = await Policy.externalOnly();
    const agent = httpsAgent(policy);
    assert.ok(agent);
    policy.close();
  });
});

describe("HTTP Protocol: validateRedirect", () => {
  it("allows redirect to public URL", async () => {
    const policy = await Policy.externalOnly();
    assert.doesNotThrow(() =>
      validateRedirect(policy, "https://example.com/redirected"),
    );
    policy.close();
  });

  it("blocks redirect to IMDS", async () => {
    const policy = await Policy.externalOnly();
    assert.throws(
      () =>
        validateRedirect(
          policy,
          "http://169.254.169.254/latest/meta-data/",
        ),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });

  it("blocks redirect to private IP", async () => {
    const policy = await Policy.externalOnly();
    assert.throws(
      () => validateRedirect(policy, "http://10.0.0.1/internal"),
      (err: unknown) => err instanceof RessrfBlockedError,
    );
    policy.close();
  });
});
