package ressrfstatic

import (
	"context"
	"testing"
)

// Mirrors go/ressrf/bench_test.go so the two are directly comparable:
//   go test -bench=. -benchmem ./go/ressrf/...
//   go test -bench=. -benchmem ./go/ressrf-static/...

func BenchmarkPolicyBuild(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		p, err := NewPolicyBuilder(PresetExternalOnly).Build()
		if err != nil {
			b.Fatal(err)
		}
		_ = p
	}
}

func BenchmarkIsAllowed(b *testing.B) {
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16").
		Build()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsAllowed(ctx, "https://example.com/api/v1/resource")
	}
}

func BenchmarkIsAllowedBlocked(b *testing.B) {
	ctx := context.Background()
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16").
		Build()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsAllowed(ctx, "http://192.168.1.1/admin")
	}
}

func BenchmarkIsNetworkAllowed(b *testing.B) {
	p, err := NewPolicyBuilder(PresetExternalOnly).
		WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16").
		Build()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsNetworkAllowed([]string{"93.184.216.34"})
	}
}
