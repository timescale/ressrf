// Package ressrf provides SSRF protection backed by a WASM policy engine.
package ressrf

import (
	"context"
	"encoding/json"
	"time"
)

// AuditEvent represents a structured event emitted by the SSRF policy engine.
type AuditEvent struct {
	Kind      string          `json:"kind"`
	Timestamp time.Time       `json:"timestamp,omitempty"`
	Fields    json.RawMessage `json:"fields,omitempty"`
}

// AuditSink receives audit events from the policy engine.
//
// Implement this interface to route audit events to your logging system.
// For a quick adapter from a plain function, see AuditFunc.
//
// Example with slog:
//
//	sink := ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
//	    slog.InfoContext(ctx, "ressrf.audit", "kind", e.Kind, "fields", string(e.Fields))
//	})
//
// Example with zap:
//
//	sink := ressrf.AuditFunc(func(_ context.Context, e *ressrf.AuditEvent) {
//	    logger.Info("ressrf.audit", zap.String("kind", e.Kind))
//	})
type AuditSink interface {
	Emit(ctx context.Context, event *AuditEvent)
}

// AuditFunc adapts a plain function to the AuditSink interface.
type AuditFunc func(ctx context.Context, event *AuditEvent)

// Emit calls the underlying function.
func (f AuditFunc) Emit(ctx context.Context, event *AuditEvent) { f(ctx, event) }

// MultiSink fans out events to multiple sinks.
type MultiSink []AuditSink

// Emit fans out the event to all contained sinks.
func (ms MultiSink) Emit(ctx context.Context, event *AuditEvent) {
	for _, s := range ms {
		s.Emit(ctx, event)
	}
}

// DiscardSink silently drops all events.
type DiscardSink struct{}

// Emit is a no-op.
func (DiscardSink) Emit(context.Context, *AuditEvent) {}
