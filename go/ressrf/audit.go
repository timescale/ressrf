// Package ressrf provides SSRF protection backed by a WASM policy engine.
package ressrf

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"go.uber.org/zap"
)

// AuditEvent represents a structured event emitted by the SSRF policy engine.
type AuditEvent struct {
	Kind      string          `json:"kind"`
	Timestamp time.Time       `json:"timestamp,omitempty"`
	Fields    json.RawMessage `json:"fields,omitempty"`
}

// AuditSink receives audit events from the policy engine.
type AuditSink interface {
	Emit(ctx context.Context, event *AuditEvent)
}

// MultiSink fans out events to multiple sinks.
type MultiSink []AuditSink

// Emit fans out the event to all contained sinks.
func (ms MultiSink) Emit(ctx context.Context, event *AuditEvent) {
	for _, s := range ms {
		s.Emit(ctx, event)
	}
}

// SlogSink emits audit events via the standard library slog.Logger.
type SlogSink struct {
	Logger *slog.Logger
}

// Emit logs the event using the configured slog.Logger.
func (s *SlogSink) Emit(ctx context.Context, event *AuditEvent) {
	attrs := []slog.Attr{
		slog.String("kind", event.Kind),
	}
	if event.Fields != nil {
		attrs = append(attrs, slog.String("fields", string(event.Fields)))
	}
	s.Logger.LogAttrs(ctx, slog.LevelInfo, "ressrf.audit", attrs...)
}

// ZapSink emits audit events via a zap.Logger.
type ZapSink struct {
	Logger *zap.Logger
}

// Emit logs the event using the configured zap.Logger.
func (z *ZapSink) Emit(_ context.Context, event *AuditEvent) {
	fields := []zap.Field{
		zap.String("kind", event.Kind),
	}
	if event.Fields != nil {
		fields = append(fields, zap.String("fields", string(event.Fields)))
	}
	z.Logger.Info("ressrf.audit", fields...)
}

// DiscardSink silently drops all events.
type DiscardSink struct{}

// Emit is a no-op.
func (DiscardSink) Emit(context.Context, *AuditEvent) {}
