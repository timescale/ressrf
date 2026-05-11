package ressrf

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestSSRFTechniqueVectors runs every URL in tests/vectors/ssrf_techniques.json
// through the WASM-backed `Policy.IsAllowed` and asserts the expected
// allow/block decision. Cases that require denied/trusted domain suffixes
// are skipped because the Go binding does not currently expose those
// configuration knobs (they are reachable from Rust via UriValidator only).
func TestSSRFTechniqueVectors(t *testing.T) {
	ctx := context.Background()

	policy, err := NewPolicyBuilder(PresetExternalOnly).Build(ctx)
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	defer func() { _ = policy.Close(ctx) }()

	data, err := os.ReadFile(vectorPath("ssrf_techniques.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}

	var vectors struct {
		Cases []struct {
			Name            string   `json:"name"`
			Category        string   `json:"category"`
			URL             string   `json:"url"`
			Expected        string   `json:"expected"`
			ReasonType      string   `json:"reason_type,omitempty"`
			DeniedSuffixes  []string `json:"denied_suffixes,omitempty"`
			TrustedSuffixes []string `json:"trusted_suffixes,omitempty"`
			Note            string   `json:"note,omitempty"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if len(tc.DeniedSuffixes) > 0 || len(tc.TrustedSuffixes) > 0 {
				t.Skipf("[%s] domain-suffix configuration not exposed in the Go binding", tc.Category)
			}

			err := policy.IsAllowed(ctx, tc.URL)
			switch tc.Expected {
			case "allowed":
				if err != nil {
					t.Errorf("[%s] expected allowed for %q, got: %v", tc.Category, tc.URL, err)
				}
			case "blocked":
				if err == nil {
					t.Errorf("[%s] expected blocked for %q, got allowed", tc.Category, tc.URL)
				} else if !errors.Is(err, ErrBlocked) {
					t.Errorf("[%s] expected ErrBlocked for %q, got: %v", tc.Category, tc.URL, err)
				}
			default:
				t.Fatalf("unknown expected value %q", tc.Expected)
			}
		})
	}
}
