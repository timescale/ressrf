export interface AuditEvent {
  kind: string;
  timestamp?: string;
  fields?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Parse a raw WASM audit event into the normalized AuditEvent shape.
 * The WASM core emits events with `event_type` as the discriminant.
 */
export function parseWasmEvent(raw: Record<string, unknown>): AuditEvent {
  const kind = (raw.event_type as string) ?? (raw.kind as string) ?? "unknown";
  const { event_type: _, kind: __, ...fields } = raw;
  return { kind, fields };
}

export interface AuditSink {
  emit(event: AuditEvent): void;
}

export type AuditFn = (event: AuditEvent) => void;

export class AuditFunc implements AuditSink {
  private fn: AuditFn;

  constructor(fn: AuditFn) {
    this.fn = fn;
  }

  emit(event: AuditEvent): void {
    this.fn(event);
  }
}

export class MultiSink implements AuditSink {
  private sinks: AuditSink[];

  constructor(sinks: AuditSink[]) {
    this.sinks = sinks;
  }

  emit(event: AuditEvent): void {
    for (const sink of this.sinks) {
      sink.emit(event);
    }
  }
}

export class DiscardSink implements AuditSink {
  emit(_event: AuditEvent): void {
    // no-op
  }
}
