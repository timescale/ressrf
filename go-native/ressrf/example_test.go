package ressrf_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/httpx"
)

// Example wires a Policy into an http.Client that enforces SSRF protection
// on every outbound request, every DNS-resolved IP, and every redirect hop.
func Example() {
	policy, err := ressrf.NewPolicy(ressrf.PresetExternalOnly,
		ressrf.WithCloudProviderDenies(ressrf.CloudAWS, ressrf.CloudAzure, ressrf.CloudGCP),
	)
	if err != nil {
		return
	}

	client := httpx.Client(policy)
	_, _ = client.Get("https://api.example.com/data")
}

// ExampleNewPolicy shows the available Option values.
func ExampleNewPolicy() {
	_, _ = ressrf.NewPolicy(ressrf.PresetExternalOnly,
		ressrf.WithCloudProviderDenies(ressrf.CloudAWS),
		ressrf.WithAllowedCIDRs("10.42.0.0/16"),
		ressrf.WithDeniedDomainSuffixes(".svc.cluster.local"),
		ressrf.WithURLAllow(ressrf.URLRuleGlob("https", "*.stripe.com", "/v1/**")),
	)
}

// ExampleNewAllowListPolicy shows the allow-list constructor. The seed is
// required; an empty allowed list errors at construction. CloudServiceSuffixes
// returns the per-cloud service-domain suffixes (*.amazonaws.com / *.windows.net
// / *.googleapis.com etc.) so callers can lock egress to a specific set of
// cloud providers. Defensive denies layer on top via the same Option type
// NewPolicy uses.
func ExampleNewAllowListPolicy() {
	_, _ = ressrf.NewAllowListPolicy(ressrf.PresetExternalOnly,
		ressrf.CloudServiceSuffixes(ressrf.CloudAWS),
		ressrf.WithCloudProviderDenies(ressrf.CloudAWS),
	)
}

// ExampleURLRuleGlob builds a URL allow-rule using glob matching.
// Host glob `*` matches a single DNS label. Path glob `*` matches a single
// segment and `**` matches any depth.
func ExampleURLRuleGlob() {
	_ = ressrf.URLRuleGlob("https", "*.stripe.com", "/v1/**")
	_ = ressrf.URLRuleGlob("https", "*.stripe.com", "/v1/**").WithBypassIPCheck()
}

// ExampleURLRuleRegex matches the entire URL against an RE2 pattern.
func ExampleURLRuleRegex() {
	_ = ressrf.URLRuleRegex(`^https://api\.example\.com/.*$`)
}

// ExamplePolicy_IsAllowed performs a full URL validation: scheme allowlist,
// host check, and IP check. Returns *BlockedError on rejection;
// errors.Is(err, ErrBlocked) matches.
func ExamplePolicy_IsAllowed() {
	policy, _ := ressrf.NewPolicy(ressrf.PresetExternalOnly)

	err := policy.IsAllowed(context.Background(), "http://10.0.0.1/secret")
	if errors.Is(err, ressrf.ErrBlocked) {
		// policy rejected the URL
		_ = err
	}
}

// ExampleBlockedError shows how to extract structured rejection data via a
// type switch on BlockedError.Reason. For categorical decisions only, use
// be.Kind() which returns a DenyKind.
func ExampleBlockedError() {
	policy, _ := ressrf.NewPolicy(ressrf.PresetExternalOnly)
	err := policy.IsAllowed(context.Background(), "http://10.0.0.1/secret")

	var be *ressrf.BlockedError
	if errors.As(err, &be) {
		switch r := be.Reason.(type) {
		case *ressrf.InDenyCIDR:
			_ = r.CIDR
			_ = r.Source
		case *ressrf.SchemeNotAllowed:
			_ = r.Scheme
		case *ressrf.BareIPDeniedBeforeScheme:
			_ = r.Host
		}
		fmt.Println(be.Kind())
	}
	// Output: bare_ip_denied_before_scheme
}

// ExampleAuditFunc demonstrates wiring an audit sink that forwards events
// to slog. Sinks fire on policy creation, every URL validation, and every
// host validation.
func ExampleAuditFunc() {
	sink := ressrf.AuditFunc(func(ctx context.Context, e *ressrf.AuditEvent) {
		slog.InfoContext(ctx, "ressrf.audit",
			"kind", e.Kind,
			"fields", string(e.Fields),
		)
	})

	_, _ = ressrf.NewPolicy(ressrf.PresetExternalOnly,
		ressrf.WithAuditSink(sink),
	)
}
