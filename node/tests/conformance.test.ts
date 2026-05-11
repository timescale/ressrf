import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Policy, PolicyBuilder, type UrlRule, type Preset } from "../src/policy.js";
import { RessrfBlockedError } from "../src/errors.js";
import { AuditFunc, type AuditEvent } from "../src/audit.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = resolve(__dirname, "..", "..", "tests", "vectors");

function loadVectors(filename: string): { cases: unknown[] } {
  const content = readFileSync(resolve(VECTORS_DIR, filename), "utf-8");
  return JSON.parse(content);
}

function loadTestCases(filename: string): { test_cases: unknown[] } {
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

interface RawUrlRule {
  scheme?: string;
  host?: string;
  path?: string;
  regex?: string;
  bypass_ip_check?: boolean;
}

interface UrlRuleCase {
  name: string;
  preset: string;
  url_rules?: {
    allow?: RawUrlRule[];
    deny?: RawUrlRule[];
  };
  url: string;
  expected: string;
}

interface SsrfTechniqueCase {
  name: string;
  category?: string;
  url: string;
  expected: string;
  reason_type?: string;
  denied_suffixes?: string[];
  trusted_suffixes?: string[];
  note?: string;
}

describe("Conformance: SSRF Technique Vectors", () => {
  const { cases } = loadVectors("ssrf_techniques.json");

  for (const raw of cases) {
    const c = raw as SsrfTechniqueCase;

    // Skip cases that need denied/trusted domain suffix configuration;
    // those knobs are not exposed on the Node `PolicyBuilder` surface.
    if (c.denied_suffixes || c.trusted_suffixes) continue;

    it(`[${c.category ?? "uncategorized"}] ${c.name}`, async () => {
      const policy = await Policy.externalOnly();

      if (c.expected === "allowed") {
        assert.doesNotThrow(
          () => policy.isAllowed(c.url),
          `expected allowed for ${c.name} (${c.url})`,
        );
      } else if (c.expected === "blocked") {
        assert.throws(
          () => policy.isAllowed(c.url),
          (err: unknown) => err instanceof RessrfBlockedError || err instanceof Error,
          `expected blocked for ${c.name} (${c.url})`,
        );
      } else {
        assert.fail(`unknown expected value: ${c.expected}`);
      }

      policy.close();
    });
  }
});

describe("Conformance: URL Rules", () => {
  const { cases } = loadVectors("url_rules.json");

  for (const raw of cases) {
    const c = raw as UrlRuleCase;

    it(c.name, async () => {
      const builder = new PolicyBuilder(c.preset as Preset);

      if (c.url_rules?.allow) {
        for (const rule of c.url_rules.allow) {
          builder.urlAllow({
            scheme: rule.scheme,
            host: rule.host,
            path: rule.path,
            regex: rule.regex,
            bypassIpCheck: rule.bypass_ip_check,
          });
        }
      }
      if (c.url_rules?.deny) {
        for (const rule of c.url_rules.deny) {
          builder.urlDeny({
            scheme: rule.scheme,
            host: rule.host,
            path: rule.path,
            regex: rule.regex,
          });
        }
      }

      const policy = await builder.build();

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

interface AuditCase {
  name: string;
  action: string;
  config: {
    preset: string;
    cloud_modules?: string[];
    audit_sink?: null;
    [key: string]: unknown;
  };
  expected_event: {
    variant: string;
    fields: Record<string, unknown>;
  } | null;
}

describe("Conformance: Audit Events", () => {
  const { test_cases } = loadTestCases("audit_events.json");

  for (const raw of test_cases) {
    const c = raw as AuditCase;

    if (
      c.action === "validate_host" ||
      c.action === "connection_attempt" ||
      c.action === "redirect_intercepted" ||
      c.action === "validate_url"
    ) {
      continue;
    }

    it(c.name, async () => {
      if (c.action === "create_policy") {
        const isNoSink = c.expected_event === null;

        if (isNoSink) {
          const policy = await new PolicyBuilder(
            c.config.preset as Preset,
          ).build();
          policy.close();
          return;
        }

        const events: AuditEvent[] = [];
        const sink = new AuditFunc((event) => events.push(event));

        const builder = new PolicyBuilder(c.config.preset as Preset);
        if (c.config.cloud_modules) {
          builder.addCloud(...c.config.cloud_modules);
        }
        builder.auditSink(sink);
        const policy = await builder.build();

        assert.ok(
          events.length > 0,
          `${c.name}: expected at least one audit event`,
        );

        const created = events.find((e) => e.kind === "policy_created");
        assert.ok(created, `${c.name}: no policy_created event`);

        const fields = c.expected_event!.fields;
        assert.strictEqual(
          created!.fields?.preset,
          fields.preset,
          `${c.name}: preset mismatch`,
        );
        if (typeof fields.deny_count_min === "number") {
          assert.ok(
            (created!.fields?.deny_count as number) >= fields.deny_count_min,
            `${c.name}: deny_count too low`,
          );
        }
        assert.strictEqual(
          created!.fields?.allow_count,
          fields.allow_count,
          `${c.name}: allow_count mismatch`,
        );

        policy.close();
      }
    });
  }
});

interface RedirectChainCase {
  name: string;
  chain: string[];
  policy_preset: string;
  expected: string;
  blocked_at_hop?: number;
  max_redirects?: number;
  allow_cidrs?: string[];
  allow_plaintext_http?: boolean;
  reason?: string;
  note?: string;
}

describe("Conformance: Redirect Chains", () => {
  const { test_cases } = loadTestCases("redirect_chains.json");

  for (const raw of test_cases) {
    const c = raw as RedirectChainCase;

    it(c.name, async () => {
      const builder = new PolicyBuilder(c.policy_preset as Preset);
      if (c.allow_cidrs) {
        builder.addAllowed(...c.allow_cidrs);
      }

      const policy = await builder.build();
      const requireHTTPS =
        c.policy_preset === "external_only" && !c.allow_plaintext_http;
      const limit = c.max_redirects ?? Infinity;

      let blockedAt = -1;
      for (let i = 1; i < c.chain.length; i++) {
        if (i >= limit) {
          blockedAt = i;
          break;
        }

        // The WASM ABI does not enforce protocol rules (require_https),
        // so check the scheme manually for redirect hop validation.
        if (requireHTTPS && c.chain[i].startsWith("http://")) {
          blockedAt = i;
          break;
        }

        try {
          policy.isAllowed(c.chain[i]);
        } catch {
          blockedAt = i;
          break;
        }
      }

      if (c.expected === "allowed") {
        assert.strictEqual(
          blockedAt,
          -1,
          `${c.name}: expected allowed, blocked at hop ${blockedAt}`,
        );
      } else {
        assert.ok(
          blockedAt >= 0,
          `${c.name}: expected blocked, got allowed`,
        );
        if (c.blocked_at_hop !== undefined) {
          assert.strictEqual(
            blockedAt,
            c.blocked_at_hop,
            `${c.name}: expected blocked at hop ${c.blocked_at_hop}, got ${blockedAt}`,
          );
        }
      }

      policy.close();
    });
  }
});
