package ressrf

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func vectorPath(name string) string {
	return filepath.Join("..", "..", "tests", "vectors", name)
}

func TestURLValidation(t *testing.T) {
	ctx := context.Background()
	policy, err := NewPolicyBuilder(PresetExternalOnly).Build(ctx)
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	defer func() { _ = policy.Close(ctx) }()

	data, err := os.ReadFile(vectorPath("url_validation.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			Name            string   `json:"name"`
			URL             string   `json:"url"`
			Expected        string   `json:"expected"`
			DeniedSuffixes  []string `json:"denied_suffixes,omitempty"`
			TrustedSuffixes []string `json:"trusted_suffixes,omitempty"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			// Cases requiring domain suffix config use a different WASM ABI path
			if len(tc.DeniedSuffixes) > 0 || len(tc.TrustedSuffixes) > 0 {
				t.Skip("domain suffix tests covered by TestURIInDomain")
			}

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

	data, err := os.ReadFile(vectorPath("policy_decisions.json"))
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

			builder := NewPolicyBuilder(preset)
			if len(tc.Allow) > 0 {
				builder.WithAllowedCIDRs(tc.Allow...)
			}
			if len(tc.CloudProviders) > 0 {
				builder.WithCloudProviders(tc.CloudProviders...)
			}

			policy, err := builder.Build(ctx)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			defer func() { _ = policy.Close(ctx) }()

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
	err := &BlockedError{Reason: "test", URL: "http://example.com"}
	if !errors.Is(err, ErrBlocked) {
		t.Fatal("BlockedError should match ErrBlocked via errors.Is")
	}
}

func TestCloudProviders(t *testing.T) {
	ctx := context.Background()

	t.Run("aws blocks IMDS", func(t *testing.T) {
		policy, err := NewPolicyBuilder(PresetExternalOnly).
			WithCloudProviders("aws").
			Build(ctx)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		defer func() { _ = policy.Close(ctx) }()

		err = policy.IsNetworkAllowed(ctx, []string{"169.254.169.254"})
		if err == nil {
			t.Error("expected IMDS to be blocked")
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("expected ErrBlocked, got: %v", err)
		}
	})

	t.Run("azure blocks wireserver", func(t *testing.T) {
		policy, err := NewPolicyBuilder(PresetExternalOnly).
			WithCloudProviders("azure").
			Build(ctx)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		defer func() { _ = policy.Close(ctx) }()

		err = policy.IsNetworkAllowed(ctx, []string{"168.63.129.16"})
		if err == nil {
			t.Error("expected wireserver to be blocked")
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("expected ErrBlocked, got: %v", err)
		}
	})

	t.Run("gcp blocks metadata", func(t *testing.T) {
		policy, err := NewPolicyBuilder(PresetExternalOnly).
			WithCloudProviders("gcp").
			Build(ctx)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		defer func() { _ = policy.Close(ctx) }()

		err = policy.IsNetworkAllowed(ctx, []string{"169.254.169.254"})
		if err == nil {
			t.Error("expected metadata endpoint to be blocked")
		} else if !errors.Is(err, ErrBlocked) {
			t.Errorf("expected ErrBlocked, got: %v", err)
		}
	})

	t.Run("multiple providers combine", func(t *testing.T) {
		policy, err := NewPolicyBuilder(PresetExternalOnly).
			WithCloudProviders("aws", "azure").
			Build(ctx)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		defer func() { _ = policy.Close(ctx) }()

		// AWS ECS metadata
		err = policy.IsNetworkAllowed(ctx, []string{"169.254.170.2"})
		if err == nil {
			t.Error("expected ECS metadata to be blocked")
		}
		// Azure wireserver
		err = policy.IsNetworkAllowed(ctx, []string{"168.63.129.16"})
		if err == nil {
			t.Error("expected wireserver to be blocked")
		}
	})

	t.Run("public IP still allowed", func(t *testing.T) {
		policy, err := NewPolicyBuilder(PresetExternalOnly).
			WithCloudProviders("aws", "azure", "gcp").
			Build(ctx)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		defer func() { _ = policy.Close(ctx) }()

		err = policy.IsNetworkAllowed(ctx, []string{"93.184.216.34"})
		if err != nil {
			t.Errorf("expected public IP to be allowed, got: %v", err)
		}
	})
}

func TestURLRulesConformance(t *testing.T) {
	ctx := context.Background()

	data, err := os.ReadFile(vectorPath("url_rules.json"))
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

			builder := NewPolicyBuilder(preset)
			if tc.URLRules != nil {
				for _, rule := range tc.URLRules.Allow {
					builder.WithURLAllow(rule)
				}
				for _, rule := range tc.URLRules.Deny {
					builder.WithURLDeny(rule)
				}
			}

			policy, err := builder.Build(ctx)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			defer func() { _ = policy.Close(ctx) }()

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

func TestDisableForTests(t *testing.T) {
	DisableForTests(t)
	ctx := context.Background()
	policy, err := NewPolicyBuilder(PresetExternalOnly).Build(ctx)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = policy.Close(ctx) }()

	if err := policy.IsAllowed(ctx, "http://127.0.0.1/"); err != nil {
		t.Errorf("expected allowed when disabled, got: %v", err)
	}
}
