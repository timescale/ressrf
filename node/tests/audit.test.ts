import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AuditFunc,
  MultiSink,
  DiscardSink,
  type AuditEvent,
} from "../src/audit.js";
import { Policy } from "../src/policy.js";

describe("AuditFunc", () => {
  it("receives events via callback", () => {
    const events: AuditEvent[] = [];
    const sink = new AuditFunc((event) => events.push(event));

    sink.emit({ kind: "test_event", fields: { key: "value" } });
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].kind, "test_event");
    assert.deepStrictEqual(events[0].fields, { key: "value" });
  });
});

describe("MultiSink", () => {
  it("fans out to multiple sinks", () => {
    const events1: AuditEvent[] = [];
    const events2: AuditEvent[] = [];
    const sink = new MultiSink([
      new AuditFunc((e) => events1.push(e)),
      new AuditFunc((e) => events2.push(e)),
    ]);

    sink.emit({ kind: "multi_test" });
    assert.strictEqual(events1.length, 1);
    assert.strictEqual(events2.length, 1);
  });
});

describe("DiscardSink", () => {
  it("does not throw", () => {
    const sink = new DiscardSink();
    assert.doesNotThrow(() => sink.emit({ kind: "discarded" }));
  });
});

describe("Audit integration with Policy", () => {
  it("receives policy_created event from WASM", async () => {
    const events: AuditEvent[] = [];
    const sink = new AuditFunc((event) => events.push(event));

    const policy = await Policy.create({
      preset: "external_only",
      auditSink: sink,
    });

    assert.ok(events.length > 0, "should have received at least one audit event");
    const created = events.find((e) => e.kind === "policy_created");
    assert.ok(created, "should have a policy_created event");
    assert.ok(created.fields, "event should have fields");
    assert.strictEqual(created.fields!.preset, "ExternalOnly");
    policy.close();
  });
});
