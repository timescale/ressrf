package ressrf

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestSlogSinkEmitsEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	sink := &SlogSink{Logger: logger}

	event := &AuditEvent{
		Kind:   "request_blocked",
		Fields: json.RawMessage(`{"url":"http://10.0.0.1"}`),
	}
	sink.Emit(context.Background(), event)

	output := buf.String()
	if !strings.Contains(output, "ressrf.audit") {
		t.Fatalf("expected log message to contain 'ressrf.audit', got: %s", output)
	}
	if !strings.Contains(output, "request_blocked") {
		t.Fatalf("expected log to contain event kind, got: %s", output)
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Fatalf("expected log to contain fields, got: %s", output)
	}
}

func TestZapSinkEmitsEvent(t *testing.T) {
	var buf bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.InfoLevel)
	logger := zap.New(core)

	sink := &ZapSink{Logger: logger}

	event := &AuditEvent{
		Kind:   "policy_created",
		Fields: json.RawMessage(`{"preset":"external_only"}`),
	}
	sink.Emit(context.Background(), event)
	_ = logger.Sync()

	output := buf.String()
	if !strings.Contains(output, "ressrf.audit") {
		t.Fatalf("expected zap log to contain 'ressrf.audit', got: %s", output)
	}
	if !strings.Contains(output, "policy_created") {
		t.Fatalf("expected zap log to contain event kind, got: %s", output)
	}
}

func TestMultiSinkFansOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger1 := slog.New(slog.NewJSONHandler(&buf1, nil))
	logger2 := slog.New(slog.NewJSONHandler(&buf2, nil))

	multi := MultiSink{
		&SlogSink{Logger: logger1},
		&SlogSink{Logger: logger2},
	}

	event := &AuditEvent{
		Kind: "test_event",
	}
	multi.Emit(context.Background(), event)

	if !strings.Contains(buf1.String(), "test_event") {
		t.Fatal("sink1 did not receive event")
	}
	if !strings.Contains(buf2.String(), "test_event") {
		t.Fatal("sink2 did not receive event")
	}
}

func TestDiscardSinkDoesNotPanic(t *testing.T) {
	sink := DiscardSink{}
	event := &AuditEvent{Kind: "some_event"}
	sink.Emit(context.Background(), event)
}

func TestSlogSinkNilFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	sink := &SlogSink{Logger: logger}

	event := &AuditEvent{
		Kind:   "event_no_fields",
		Fields: nil,
	}
	sink.Emit(context.Background(), event)

	output := buf.String()
	if !strings.Contains(output, "event_no_fields") {
		t.Fatalf("expected log to contain event kind, got: %s", output)
	}
}
