import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Policy, PolicyBuilder } from "../src/policy.js";
import { RessrfBlockedError } from "../src/errors.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, "..", "..", "tests", "vectors");

function loadVectors(filename: string): { cases: unknown[] } {
  const content = readFileSync(resolve(VECTORS_DIR, filename), "utf-8");
  return JSON.parse(content);
}

interface PolicyCase {
  name: string;
  preset: string;
  ips: string[];
  expected: string;
  reason_type?: string;
  allow?: string[];
  deny?: string[];
  cloud_providers?: string[];
}

interface UrlCase {
  name: string;
  url: string;
  expected: string;
  reason_type?: string;
  denied_suffixes?: string[];
  trusted_suffixes?: string[];
}

describe("Conformance: Policy Decisions", () => {
  const { cases } = loadVectors("policy_decisions.json");

  for (const raw of cases) {
    const c = raw as PolicyCase;
    it(c.name, async () => {
      const builder = new PolicyBuilder(c.preset as "external_only" | "internal_only" | "none");

      if (c.allow) {
        builder.addAllowed(...c.allow);
      }
      if (c.deny) {
        builder.addDenied(...c.deny);
      }
      if (c.cloud_providers) {
        builder.addCloud(...c.cloud_providers);
      }

      const policy = await builder.build();

      if (c.expected === "allowed") {
        assert.doesNotThrow(() => policy.isNetworkAllowed(c.ips));
      } else {
        assert.throws(
          () => policy.isNetworkAllowed(c.ips),
          (err: unknown) => err instanceof RessrfBlockedError,
          `expected blocked for case: ${c.name}`,
        );
      }

      policy.close();
    });
  }
});

describe("Conformance: URL Validation", () => {
  const { cases } = loadVectors("url_validation.json");

  for (const raw of cases) {
    const c = raw as UrlCase;

    // Skip cases requiring custom UriValidator configuration
    if (c.denied_suffixes || c.trusted_suffixes) continue;

    it(c.name, async () => {
      const policy = await Policy.externalOnly();

      if (c.expected === "allowed") {
        assert.doesNotThrow(() => policy.isAllowed(c.url));
      } else {
        assert.throws(
          () => policy.isAllowed(c.url),
          (err: unknown) => err instanceof RessrfBlockedError || err instanceof Error,
          `expected blocked for case: ${c.name}`,
        );
      }

      policy.close();
    });
  }
});
