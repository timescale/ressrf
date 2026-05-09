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
			Name     string   `json:"name"`
			Preset   string   `json:"preset"`
			IPs      []string `json:"ips"`
			Expected string   `json:"expected"`
			Allow    []string `json:"allow"`
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
