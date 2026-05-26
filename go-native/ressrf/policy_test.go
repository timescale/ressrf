package ressrf

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/timescale/ressrf/go-native/ressrf/internal/testvectors"
)

// asCloudProviders converts vector-loaded JSON string names into the typed
// CloudProvider slice that the construction APIs take. Routes through
// ParseCloudProvider since the public CloudProvider type is no longer a
// named string and cannot be constructed by cast.
func asCloudProviders(tb testing.TB, names []string) []CloudProvider {
	tb.Helper()
	out := make([]CloudProvider, len(names))
	for i, n := range names {
		p, err := ParseCloudProvider(n)
		if err != nil {
			tb.Fatalf("asCloudProviders: %v", err)
		}
		out[i] = p
	}
	return out
}

// policyForCase returns base unchanged when the case has no suffix config,
// or a fresh per-case policy when it does. The presence of an allow-list
// seed selects the constructor: NewAllowListPolicy for non-empty seed,
// NewPolicy otherwise. Used by table-driven vector tests.
func policyForCase(tb testing.TB, base *Policy, denied, allowList []string) *Policy {
	tb.Helper()
	if len(denied) == 0 && len(allowList) == 0 {
		return base
	}
	var opts []Option
	if len(denied) > 0 {
		opts = append(opts, WithDeniedDomainSuffixes(denied...))
	}
	var (
		p   *Policy
		err error
	)
	if len(allowList) > 0 {
		p, err = NewAllowListPolicy(PresetExternalOnly, allowList, opts...)
	} else {
		p, err = NewPolicy(PresetExternalOnly, opts...)
	}
	if err != nil {
		tb.Fatalf("build per-case policy: %v", err)
	}
	return p
}

func TestURLValidation(t *testing.T) {
	ctx := context.Background()
	basePolicy, err := NewPolicy(PresetExternalOnly)
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	data, err := testvectors.Read("url_validation.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			Name              string   `json:"name"`
			URL               string   `json:"url"`
			Expected          string   `json:"expected"`
			DeniedSuffixes    []string `json:"denied_suffixes,omitempty"`
			AllowListSuffixes []string `json:"trusted_suffixes,omitempty"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			policy := policyForCase(t, basePolicy, tc.DeniedSuffixes, tc.AllowListSuffixes)

			err := policy.IsAllowed(ctx, tc.URL)
			switch tc.Expected {
			case "allowed":
				if err != nil {
					t.Errorf("expected allowed, got: %v", err)
				}
			case "blocked":
				if err == nil {
					t.Errorf("expected blocked, got allowed")
				} else if !errors.Is(err, ErrBlocked) {
					t.Errorf("expected ErrBlocked, got: %v", err)
				}
			}
		})
	}
}

func TestPolicyDecisions(t *testing.T) {
	ctx := context.Background()

	data, err := testvectors.Read("policy_decisions.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			Name           string   `json:"name"`
			Preset         string   `json:"preset"`
			IPs            []string `json:"ips"`
			Expected       string   `json:"expected"`
			Allow          []string `json:"allow"`
			CloudProviders []string `json:"cloud_providers"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var preset Preset
			switch tc.Preset {
			case "external_only":
				preset = PresetExternalOnly
			case "internal_only":
				preset = PresetInternalOnly
			default:
				preset = PresetNone
			}

			opts := []Option{}
			if len(tc.Allow) > 0 {
				opts = append(opts, WithAllowedCIDRs(tc.Allow...))
			}
			if len(tc.CloudProviders) > 0 {
				// This vector exercises IsNetworkAllowed (IP layer); IP-layer
				// behaviour doesn't depend on URI-validator mode, so the
				// defensive-deny option alone is enough.
				opts = append(opts, WithCloudProviderDenies(asCloudProviders(t, tc.CloudProviders)...))
			}

			policy, err := NewPolicy(preset, opts...)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			err = policy.IsNetworkAllowed(ctx, tc.IPs)
			switch tc.Expected {
			case "allowed":
				if err != nil {
					t.Errorf("expected allowed, got: %v", err)
				}
			case "blocked":
				if err == nil {
					t.Errorf("expected blocked, got allowed")
				} else if !errors.Is(err, ErrBlocked) {
					t.Errorf("expected ErrBlocked, got: %v", err)
				}
			}
		})
	}
}

func TestErrBlockedSentinel(t *testing.T) {
	err := &BlockedError{Detail: "test", URL: "http://example.com"}
	if !errors.Is(err, ErrBlocked) {
		t.Fatal("BlockedError should match ErrBlocked via errors.Is")
	}
}

func TestCloudProviderDenies(t *testing.T) {
	ctx := context.Background()

	t.Run("aws blocks IMDS", func(t *testing.T) {
		policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudAWS))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsNetworkAllowed(ctx, []string{"169.254.169.254"})
		if err == nil {
			t.Error("expected IMDS to be blocked")
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("expected ErrBlocked, got: %v", err)
		}
	})

	t.Run("azure blocks wireserver", func(t *testing.T) {
		policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudAzure))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsNetworkAllowed(ctx, []string{"168.63.129.16"})
		if err == nil {
			t.Error("expected wireserver to be blocked")
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("expected ErrBlocked, got: %v", err)
		}
	})

	t.Run("gcp blocks metadata", func(t *testing.T) {
		policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudGCP))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsNetworkAllowed(ctx, []string{"169.254.169.254"})
		if err == nil {
			t.Error("expected metadata endpoint to be blocked")
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("expected ErrBlocked, got: %v", err)
		}
	})

	t.Run("multiple providers combine", func(t *testing.T) {
		policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudAWS, CloudAzure))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		// AWS ECS metadata
		if err := policy.IsNetworkAllowed(ctx, []string{"169.254.170.2"}); err == nil {
			t.Error("expected ECS metadata to be blocked")
		}
		// Azure wireserver
		if err := policy.IsNetworkAllowed(ctx, []string{"168.63.129.16"}); err == nil {
			t.Error("expected wireserver to be blocked")
		}
	})

	t.Run("public IP still allowed", func(t *testing.T) {
		policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudAWS, CloudAzure, CloudGCP))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if err := policy.IsNetworkAllowed(ctx, []string{"93.184.216.34"}); err != nil {
			t.Errorf("expected public IP to be allowed, got: %v", err)
		}
	})
}

// TestPolicyMode pins the consumer-visible distinction between NewPolicy
// (deny-only; non-IP hosts pass unless explicitly denied) and
// NewAllowListPolicy (locks egress to the supplied seed list). The split
// replaces the old bundled WithCloudProviders option, which silently flipped
// the URI validator into allow-list mode and rejected every customer hostname
// not under a cloud service suffix. Mode-flipping is now structural: only
// NewAllowListPolicy enables it, and no Option can.
func TestPolicyMode(t *testing.T) {
	ctx := context.Background()

	// A real-shape Confluent Cloud schema-registry URL. Not under any cloud
	// service suffix. This is the host shape that broke tiger-connect#402.
	const customerHost = "https://psrc-abc.us-east-2.aws.confluent.cloud"

	t.Run("NewPolicy + WithCloudProviderDenies stays in deny-only mode", func(t *testing.T) {
		policy, err := NewPolicy(PresetExternalOnly,
			WithCloudProviderDenies(CloudAWS, CloudAzure, CloudGCP),
		)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		// Customer URL outside any cloud service suffix must NOT be rejected:
		// NewPolicy never enables allow-list mode, regardless of which options
		// are passed.
		if err := policy.IsAllowed(ctx, customerHost); err != nil {
			t.Errorf("NewPolicy rejected customer host %q: %v", customerHost, err)
		}
		// Provider-specific extras still fire at the IP layer (AWS ECS metadata).
		if err := policy.IsNetworkAllowed(ctx, []string{"169.254.170.2"}); err == nil {
			t.Error("expected ECS metadata IP to remain blocked under WithCloudProviderDenies")
		}
		// Internal-DNS suffix still fires at the URL layer (AWS .compute.internal).
		err = policy.IsAllowed(ctx, "https://worker.compute.internal")
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("expected *BlockedError for AWS internal suffix, got: %v", err)
		}
		if _, ok := blocked.Reason.(*DomainSuffixDenied); !ok {
			t.Errorf("expected DomainSuffixDenied, got %T: %v", blocked.Reason, blocked)
		}
	})

	t.Run("NewAllowListPolicy locks egress to the seed suffixes", func(t *testing.T) {
		policy, err := NewAllowListPolicy(PresetExternalOnly,
			CloudServiceSuffixes(CloudAWS),
		)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		// Host under the seed suffix is allowed.
		if err := policy.IsAllowed(ctx, "https://api.amazonaws.com"); err != nil {
			t.Errorf("seed-suffix host rejected: %v", err)
		}
		// Customer URL outside the seed suffix is rejected with DomainNotInAllowList.
		err = policy.IsAllowed(ctx, customerHost)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("expected *BlockedError for %q, got: %v", customerHost, err)
		}
		if _, ok := blocked.Reason.(*DomainNotInAllowList); !ok {
			t.Errorf("expected DomainNotInAllowList, got %T: %v", blocked.Reason, blocked)
		}
	})

	t.Run("NewAllowListPolicy composes additive denies on top", func(t *testing.T) {
		// Callers who want the legacy bundled semantics (allow-list locked to
		// cloud service suffixes AND per-cloud defensive denies) layer denies
		// on top of NewAllowListPolicy. The mode flip is in the constructor
		// name; the denies are an additive option. No single-option footgun.
		policy, err := NewAllowListPolicy(PresetExternalOnly,
			CloudServiceSuffixes(CloudAWS, CloudAzure, CloudGCP),
			WithCloudProviderDenies(CloudAWS, CloudAzure, CloudGCP),
		)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsAllowed(ctx, customerHost)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("expected *BlockedError under allow-list mode for %q, got: %v", customerHost, err)
		}
		if _, ok := blocked.Reason.(*DomainNotInAllowList); !ok {
			t.Errorf("expected DomainNotInAllowList under allow-list mode, got %T: %v", blocked.Reason, blocked)
		}
	})

	t.Run("NewAllowListPolicy rejects empty seed list", func(t *testing.T) {
		// Empty allow-list would reject every non-IP host, which is almost
		// certainly a caller bug (forgotten config wiring, dropped append).
		// The constructor errors loudly rather than producing a deny-all policy.
		// Asserting errors.Is against the sentinel pins the error identity so
		// a future message edit can't silently break callers that branch on it.
		_, err := NewAllowListPolicy(PresetExternalOnly, nil)
		if !errors.Is(err, ErrEmptyAllowList) {
			t.Fatalf("expected ErrEmptyAllowList for nil seed, got: %v", err)
		}
		_, err = NewAllowListPolicy(PresetExternalOnly, []string{})
		if !errors.Is(err, ErrEmptyAllowList) {
			t.Fatalf("expected ErrEmptyAllowList for empty seed, got: %v", err)
		}
	})

	t.Run("denied suffix wins over allow-list match", func(t *testing.T) {
		// The validator checks denies before the allow-list. A host that
		// matches both an allowed suffix AND a denied suffix is denied.
		// Pinning this so a future reorder of the validator's checks can't
		// silently flip precedence.
		policy, err := NewAllowListPolicy(PresetExternalOnly,
			[]string{"example.com"},
			WithDeniedDomainSuffixes(".bad.example.com"),
		)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsAllowed(ctx, "https://api.bad.example.com")
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("expected *BlockedError, got: %v", err)
		}
		if _, ok := blocked.Reason.(*DomainSuffixDenied); !ok {
			t.Errorf("expected DomainSuffixDenied (deny wins), got %T: %v", blocked.Reason, blocked)
		}
	})

	t.Run("URL allow without bypassIPCheck still hits allow-list mode", func(t *testing.T) {
		// Plain WithURLAllow doesn't short-circuit the validator. A URL that
		// matches an allow rule but has a host outside the seed still gets
		// rejected with DomainNotInAllowList. Documents the precedence: URL
		// rules evaluate first, but only URLAllowedBypassIP skips the
		// validator; URLAllowed falls through.
		policy, err := NewAllowListPolicy(PresetExternalOnly,
			[]string{"amazonaws.com"},
			WithURLAllow(URLRuleGlob("https", "*.foo.com", "/api/**")),
		)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsAllowed(ctx, "https://api.foo.com/api/v1")
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("expected *BlockedError, got: %v", err)
		}
		if _, ok := blocked.Reason.(*DomainNotInAllowList); !ok {
			t.Errorf("expected DomainNotInAllowList (validator fires after URL allow), got %T: %v", blocked.Reason, blocked)
		}
	})

	t.Run("URL allow with bypassIPCheck overrides allow-list mode", func(t *testing.T) {
		// WithBypassIPCheck is the explicit escape hatch: matching URLs
		// short-circuit the validator (and the IP check). Without it,
		// allow-list mode couldn't be relaxed for specific URL patterns.
		policy, err := NewAllowListPolicy(PresetExternalOnly,
			[]string{"amazonaws.com"},
			WithURLAllow(URLRuleGlob("https", "*.foo.com", "/api/**").WithBypassIPCheck()),
		)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if err := policy.IsAllowed(ctx, "https://api.foo.com/api/v1"); err != nil {
			t.Errorf("expected URL allow with bypass to override allow-list, got: %v", err)
		}
	})

	t.Run("NewAllowListPolicy with PresetNone still locks egress", func(t *testing.T) {
		// The URI validator's allow-list check is preset-independent today, so
		// PresetNone + a seed still rejects non-matching hosts. Without this
		// pin, a future refactor that ties URI-validator engagement to the
		// preset would silently turn this constructor into permit-all.
		policy, err := NewAllowListPolicy(PresetNone, []string{"amazonaws.com"})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		err = policy.IsAllowed(ctx, customerHost)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("expected *BlockedError under PresetNone allow-list, got: %v", err)
		}
		if _, ok := blocked.Reason.(*DomainNotInAllowList); !ok {
			t.Errorf("expected DomainNotInAllowList under PresetNone, got %T: %v", blocked.Reason, blocked)
		}
	})
}

// TestPolicy_UnknownPreset pins the construction-time rejection of out-of-range
// Preset values. The mapping function still has a safe default (PresetNone)
// for any future engine.Preset value the public surface hasn't caught up to,
// but the public constructors now reject up front rather than silently
// downgrading to permit-all.
func TestPolicy_UnknownPreset(t *testing.T) {
	_, err := NewPolicy(Preset(99))
	if !errors.Is(err, ErrUnknownPreset) {
		t.Fatalf("expected ErrUnknownPreset from NewPolicy(Preset(99)), got: %v", err)
	}

	_, err = NewAllowListPolicy(Preset(99), []string{"example.com"})
	if !errors.Is(err, ErrUnknownPreset) {
		t.Fatalf("expected ErrUnknownPreset from NewAllowListPolicy(Preset(99), ...), got: %v", err)
	}
}

// TestParseCloudProvider exercises the only string-to-CloudProvider boundary.
// The compile-time constraint on the type (unexported field) makes typoed
// CloudProvider literals uncompilable; ParseCloudProvider is the surface
// where dynamic-config callers (CLI flag, env var, JSON) turn untrusted
// strings into typed values and where ErrUnknownCloudProvider can still
// fire. Case-insensitivity matches the engine's internal normalization so
// "AWS", "aws", " Aws " all resolve to CloudAWS.
func TestParseCloudProvider(t *testing.T) {
	cases := []struct {
		in   string
		want CloudProvider
	}{
		{"aws", CloudAWS},
		{"AWS", CloudAWS},
		{" Aws ", CloudAWS},
		{"azure", CloudAzure},
		{"AZURE", CloudAzure},
		{"gcp", CloudGCP},
	}
	for _, tc := range cases {
		got, err := ParseCloudProvider(tc.in)
		if err != nil {
			t.Errorf("ParseCloudProvider(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseCloudProvider(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"awz", "azuer", "", "  ", "aws-china", "AmazonWebServices"} {
		_, err := ParseCloudProvider(bad)
		if !errors.Is(err, ErrUnknownCloudProvider) {
			t.Errorf("ParseCloudProvider(%q): expected ErrUnknownCloudProvider, got %v", bad, err)
		}
	}
}

// TestCloudProviderZeroValueIsHarmless pins that the zero value is silently
// skipped by both surfaces that take CloudProvider as input. Doing this in
// a test rather than at runtime keeps the WithCloudProviderDenies signature
// from leaking an error return; misuse via CloudProvider{} is rare enough
// that "skip and let the missing denies show up in the caller's tests" is
// the right tradeoff.
func TestCloudProviderZeroValueIsHarmless(t *testing.T) {
	// WithCloudProviderDenies with only the zero value: builds, no denies added.
	policy, err := NewPolicy(PresetExternalOnly, WithCloudProviderDenies(CloudProvider{}))
	if err != nil {
		t.Fatalf("build with zero-value CloudProvider failed: %v", err)
	}
	// 169.254.169.254 stays blocked because PresetExternalOnly's baseline
	// covers it; this only confirms the build didn't error.
	if err := policy.IsNetworkAllowed(context.Background(), []string{"169.254.169.254"}); err == nil {
		t.Error("expected baseline preset deny to still fire")
	}

	// CloudServiceSuffixes with only the zero value: returns nil.
	if got := CloudServiceSuffixes(CloudProvider{}); got != nil {
		t.Errorf("CloudServiceSuffixes(CloudProvider{}) = %v, want nil", got)
	}
}

func TestURLRulesConformance(t *testing.T) {
	ctx := context.Background()

	data, err := testvectors.Read("url_rules.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			Name     string `json:"name"`
			Preset   string `json:"preset"`
			URLRules *struct {
				Allow []URLRule `json:"allow"`
				Deny  []URLRule `json:"deny"`
			} `json:"url_rules"`
			URL      string `json:"url"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var preset Preset
			switch tc.Preset {
			case "external_only":
				preset = PresetExternalOnly
			case "internal_only":
				preset = PresetInternalOnly
			default:
				preset = PresetNone
			}

			opts := []Option{}
			if tc.URLRules != nil {
				for _, rule := range tc.URLRules.Allow {
					opts = append(opts, WithURLAllow(rule))
				}
				for _, rule := range tc.URLRules.Deny {
					opts = append(opts, WithURLDeny(rule))
				}
			}

			policy, err := NewPolicy(preset, opts...)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			err = policy.IsAllowed(ctx, tc.URL)
			switch tc.Expected {
			case "allowed":
				if err != nil {
					t.Errorf("expected allowed, got: %v", err)
				}
			case "blocked":
				if err == nil {
					t.Errorf("expected blocked, got allowed")
				} else if !errors.Is(err, ErrBlocked) {
					t.Errorf("expected ErrBlocked, got: %v", err)
				}
			}
		})
	}
}

func TestAuditEventVectors(t *testing.T) {
	data, err := testvectors.Read("audit_events.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		TestCases []struct {
			Name          string           `json:"name"`
			Action        string           `json:"action"`
			Config        json.RawMessage  `json:"config"`
			ExpectedEvent *json.RawMessage `json:"expected_event"`
		} `json:"test_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.TestCases {
		switch tc.Action {
		case "create_policy":
			t.Run(tc.Name, func(t *testing.T) {
				var cfg struct {
					Preset       string   `json:"preset"`
					CloudModules []string `json:"cloud_modules"`
					AuditSink    *string  `json:"audit_sink"`
				}
				if err := json.Unmarshal(tc.Config, &cfg); err != nil {
					t.Fatalf("parse config: %v", err)
				}

				isNoSinkCase := tc.ExpectedEvent == nil

				if isNoSinkCase {
					// Build without audit sink; verify no panic.
					if _, err := NewPolicy(presetFrom(cfg.Preset)); err != nil {
						t.Fatalf("build: %v", err)
					}
					return
				}

				var mu sync.Mutex
				var events []AuditEvent
				sink := AuditFunc(func(_ context.Context, e *AuditEvent) {
					mu.Lock()
					events = append(events, *e)
					mu.Unlock()
				})

				opts := []Option{WithAuditSink(sink)}
				if len(cfg.CloudModules) > 0 {
					// Audit-event vector: only the policy-creation event matters,
					// no URI-validator hits. Defensive-deny option is enough.
					opts = append(opts, WithCloudProviderDenies(asCloudProviders(t, cfg.CloudModules)...))
				}
				if _, err := NewPolicy(presetFrom(cfg.Preset), opts...); err != nil {
					t.Fatalf("build: %v", err)
				}

				mu.Lock()
				count := len(events)
				mu.Unlock()

				if count == 0 {
					t.Error("expected at least one audit event from policy creation")
				}
			})
		case "validate_url", "validate_host", "connection_attempt", "redirect_intercepted":
			// These event types are not yet emitted by the WASM core.
		default:
			t.Errorf("unknown action: %s", tc.Action)
		}
	}
}

func TestRedirectChainVectors(t *testing.T) {
	ctx := context.Background()

	data, err := testvectors.Read("redirect_chains.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		TestCases []struct {
			Name               string   `json:"name"`
			Chain              []string `json:"chain"`
			PolicyPreset       string   `json:"policy_preset"`
			Expected           string   `json:"expected"`
			BlockedAtHop       *int     `json:"blocked_at_hop"`
			MaxRedirects       *int     `json:"max_redirects"`
			AllowCIDRs         []string `json:"allow_cidrs"`
			AllowPlaintextHTTP bool     `json:"allow_plaintext_http"`
		} `json:"test_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.TestCases {
		t.Run(tc.Name, func(t *testing.T) {
			opts := []Option{}
			if len(tc.AllowCIDRs) > 0 {
				opts = append(opts, WithAllowedCIDRs(tc.AllowCIDRs...))
			}

			policy, err := NewPolicy(presetFrom(tc.PolicyPreset), opts...)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			limit := -1
			if tc.MaxRedirects != nil {
				limit = *tc.MaxRedirects
			}

			requireHTTPS := tc.PolicyPreset == "external_only" && !tc.AllowPlaintextHTTP

			blockedAt := -1
			for i := 1; i < len(tc.Chain); i++ {
				if limit >= 0 && i >= limit {
					blockedAt = i
					break
				}

				// The WASM ABI does not enforce protocol rules (require_https),
				// so we check the scheme manually for redirect hop validation.
				if requireHTTPS && strings.HasPrefix(tc.Chain[i], "http://") {
					blockedAt = i
					break
				}

				if err := policy.IsAllowed(ctx, tc.Chain[i]); err != nil {
					blockedAt = i
					break
				}
			}

			switch tc.Expected {
			case "allowed":
				if blockedAt >= 0 {
					t.Errorf("expected allowed, blocked at hop %d", blockedAt)
				}
			case "blocked":
				if blockedAt < 0 {
					t.Error("expected blocked, got allowed")
				} else if tc.BlockedAtHop != nil && blockedAt != *tc.BlockedAtHop {
					t.Errorf("expected blocked at hop %d, got %d", *tc.BlockedAtHop, blockedAt)
				}
			}
		})
	}
}

func presetFrom(s string) Preset {
	switch s {
	case "external_only":
		return PresetExternalOnly
	case "internal_only":
		return PresetInternalOnly
	default:
		return PresetNone
	}
}

func TestDisableForTests(t *testing.T) {
	DisableForTests(t)
	ctx := context.Background()
	policy, err := NewPolicy(PresetExternalOnly)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if err := policy.IsAllowed(ctx, "http://127.0.0.1/"); err != nil {
		t.Errorf("expected allowed when disabled, got: %v", err)
	}
}
