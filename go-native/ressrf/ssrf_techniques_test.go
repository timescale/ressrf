package ressrf

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/timescale/ressrf/go-native/ressrf/internal/testvectors"
)

// TestSSRFTechniqueVectors runs every URL in tests/vectors/ssrf_techniques.json
// through Policy.IsAllowed and asserts the expected allow/block decision.
// Cases carrying denied/trusted suffix lists get a fresh per-case policy
// via policyForCase: denied suffixes flow through WithDeniedDomainSuffixes,
// trusted suffixes seed NewAllowListPolicy.
func TestSSRFTechniqueVectors(t *testing.T) {
	ctx := context.Background()

	basePolicy, err := NewPolicy(PresetExternalOnly)
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	data, err := testvectors.Read("ssrf_techniques.json")
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
			policy := policyForCase(t, basePolicy, tc.DeniedSuffixes, tc.TrustedSuffixes)

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
