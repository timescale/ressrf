package ressrf

import (
	"context"
	"testing"
)

func BenchmarkPolicyBuild(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewPolicy(PresetExternalOnly); err != nil {
			b.Fatal(err)
		}
	}
}

func benchPolicy(b *testing.B) *Policy {
	b.Helper()
	p, err := NewPolicy(PresetExternalOnly,
		WithDeniedCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
	)
	if err != nil {
		b.Fatal(err)
	}
	return p
}

func BenchmarkIsAllowed(b *testing.B) {
	ctx := context.Background()
	p := benchPolicy(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsAllowed(ctx, "https://example.com/api/v1/resource")
	}
}

func BenchmarkIsAllowedBlocked(b *testing.B) {
	ctx := context.Background()
	p := benchPolicy(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsAllowed(ctx, "http://192.168.1.1/admin")
	}
}

func BenchmarkIsNetworkAllowed(b *testing.B) {
	ctx := context.Background()
	p := benchPolicy(b)
	ips := []string{"93.184.216.34"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsNetworkAllowed(ctx, ips)
	}
}

func BenchmarkIsNetworkAllowedBlocked(b *testing.B) {
	ctx := context.Background()
	p := benchPolicy(b)
	ips := []string{"10.0.0.1"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = p.IsNetworkAllowed(ctx, ips)
	}
}
