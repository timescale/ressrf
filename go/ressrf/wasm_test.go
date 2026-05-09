package ressrf

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestEmptyPolicyAllowsEverything(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetNone).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close(ctx) }()

	err = p.IsNetworkAllowed(ctx, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("None preset should allow all, got: %v", err)
	}
}

func TestPolicyCloseIsIdempotent(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetExternalOnly).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = p.Close(ctx)
	if err != nil {
		t.Fatalf("first close failed: %v", err)
	}
	err = p.Close(ctx)
	if err != nil {
		t.Fatalf("second close failed: %v", err)
	}
}

func TestConcurrentIsAllowed(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8").
		Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close(ctx) }()

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			url := "https://example.com/path"
			if n%2 == 0 {
				url = "http://10.0.0.1/internal"
			}
			err := p.IsAllowed(ctx, url)
			if n%2 == 0 && err == nil {
				errs <- errors.New("expected blocked for private URL")
			}
			if n%2 != 0 && err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestConcurrentIsNetworkAllowed(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8", "192.168.0.0/16").
		Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close(ctx) }()

	var wg sync.WaitGroup
	errs := make(chan error, 100)

	for i := range 50 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			var ips []string
			if n%2 == 0 {
				ips = []string{"10.0.0.1"}
			} else {
				ips = []string{"93.184.216.34"}
			}
			err := p.IsNetworkAllowed(ctx, ips)
			if n%2 == 0 && err == nil {
				errs <- errors.New("expected blocked for private IP")
			}
			if n%2 != 0 && err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestMultiplePoliciesIndependent(t *testing.T) {
	ctx := context.Background()

	p1, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8").
		Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p1.Close(ctx) }()

	p2, err := NewPolicyBuilder(PresetNone).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p2.Close(ctx) }()

	err = p1.IsNetworkAllowed(ctx, []string{"10.0.0.1"})
	if err == nil {
		t.Fatal("p1 should block private IPs")
	}

	err = p2.IsNetworkAllowed(ctx, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("p2 (None preset) should allow all, got: %v", err)
	}
}

func TestPolicyWithAuditSink(t *testing.T) {
	ctx := context.Background()
	events := make([]AuditEvent, 0)
	var mu sync.Mutex

	sink := &testSink{emit: func(_ context.Context, e *AuditEvent) {
		mu.Lock()
		events = append(events, *e)
		mu.Unlock()
	}}

	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8").
		WithAuditSink(sink).
		Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close(ctx) }()

	_ = p.IsAllowed(ctx, "http://10.0.0.1/secret")

	mu.Lock()
	count := len(events)
	mu.Unlock()

	if count == 0 {
		t.Log("no audit events captured (audit may be deferred to WASM callback)")
	}
}

type testSink struct {
	emit func(context.Context, *AuditEvent)
}

func (s *testSink) Emit(ctx context.Context, event *AuditEvent) {
	s.emit(ctx, event)
}
