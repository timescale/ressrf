package ressrf

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestEmptyPolicyAllowsEverything(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicy(PresetNone)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.IsNetworkAllowed(ctx, []string{"10.0.0.1"}); err != nil {
		t.Fatalf("None preset should allow all, got: %v", err)
	}
}

func TestConcurrentIsAllowed(t *testing.T) {
	ctx := context.Background()
	p, err := NewPolicy(PresetExternalOnly, WithDeniedCIDRs("10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}

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
	p, err := NewPolicy(PresetExternalOnly,
		WithDeniedCIDRs("10.0.0.0/8", "192.168.0.0/16"),
	)
	if err != nil {
		t.Fatal(err)
	}

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

	p1, err := NewPolicy(PresetExternalOnly, WithDeniedCIDRs("10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}

	p2, err := NewPolicy(PresetNone)
	if err != nil {
		t.Fatal(err)
	}

	if err := p1.IsNetworkAllowed(ctx, []string{"10.0.0.1"}); err == nil {
		t.Fatal("p1 should block private IPs")
	}

	if err := p2.IsNetworkAllowed(ctx, []string{"10.0.0.1"}); err != nil {
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

	p, err := NewPolicy(PresetExternalOnly,
		WithDeniedCIDRs("10.0.0.0/8"),
		WithAuditSink(sink),
	)
	if err != nil {
		t.Fatal(err)
	}

	_ = p.IsAllowed(ctx, "http://10.0.0.1/secret")

	mu.Lock()
	count := len(events)
	mu.Unlock()

	// PolicyCreated + URLValidated -> at least 2 events.
	if count < 2 {
		t.Errorf("expected >= 2 audit events, got %d", count)
	}
}

type testSink struct {
	emit func(context.Context, *AuditEvent)
}

func (s *testSink) Emit(ctx context.Context, event *AuditEvent) {
	s.emit(ctx, event)
}
