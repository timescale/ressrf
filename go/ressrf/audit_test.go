package ressrf

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestAuditFuncReceivesEvent(t *testing.T) {
	var captured *AuditEvent
	sink := AuditFunc(func(_ context.Context, e *AuditEvent) {
		captured = e
	})

	event := &AuditEvent{
		Kind:   "request_blocked",
		Fields: json.RawMessage(`{"url":"http://10.0.0.1"}`),
	}
	sink.Emit(context.Background(), event)

	if captured == nil {
		t.Fatal("AuditFunc did not receive event")
	}
	if captured.Kind != "request_blocked" {
		t.Fatalf("expected kind 'request_blocked', got %q", captured.Kind)
	}
	if string(captured.Fields) != `{"url":"http://10.0.0.1"}` {
		t.Fatalf("unexpected fields: %s", string(captured.Fields))
	}
}

func TestAuditFuncNilFields(t *testing.T) {
	var captured *AuditEvent
	sink := AuditFunc(func(_ context.Context, e *AuditEvent) {
		captured = e
	})

	event := &AuditEvent{Kind: "policy_created"}
	sink.Emit(context.Background(), event)

	if captured == nil {
		t.Fatal("AuditFunc did not receive event")
	}
	if captured.Fields != nil {
		t.Fatalf("expected nil fields, got: %s", string(captured.Fields))
	}
}

func TestMultiSinkFansOut(t *testing.T) {
	var count1, count2 int
	sink1 := AuditFunc(func(_ context.Context, _ *AuditEvent) { count1++ })
	sink2 := AuditFunc(func(_ context.Context, _ *AuditEvent) { count2++ })

	multi := MultiSink{sink1, sink2}

	event := &AuditEvent{Kind: "test_event"}
	multi.Emit(context.Background(), event)

	if count1 != 1 {
		t.Fatalf("sink1 expected 1 call, got %d", count1)
	}
	if count2 != 1 {
		t.Fatalf("sink2 expected 1 call, got %d", count2)
	}
}

func TestMultiSinkEmpty(t *testing.T) {
	multi := MultiSink{}
	event := &AuditEvent{Kind: "no_panic"}
	multi.Emit(context.Background(), event)
}

func TestDiscardSinkDoesNotPanic(t *testing.T) {
	sink := DiscardSink{}
	event := &AuditEvent{Kind: "some_event"}
	sink.Emit(context.Background(), event)
}

func TestAuditFuncConcurrent(t *testing.T) {
	var mu sync.Mutex
	var events []*AuditEvent

	sink := AuditFunc(func(_ context.Context, e *AuditEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sink.Emit(context.Background(), &AuditEvent{Kind: "concurrent"})
			_ = n
		}(i)
	}
	wg.Wait()

	mu.Lock()
	count := len(events)
	mu.Unlock()

	if count != 100 {
		t.Fatalf("expected 100 events, got %d", count)
	}
}
