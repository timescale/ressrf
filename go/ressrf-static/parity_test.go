package ressrfstatic

// Internal-package test so it can use the already-embedded vector JSON
// (policyDecisionsJSON, ssrfTechniquesJSON) without re-embedding via a
// public helper. Imports the WASM-backed package under an alias so both
// backends are in scope simultaneously.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	wasm "github.com/timescale/ressrf/go/ressrf"
)

type ipParityCase struct {
	Name           string   `json:"name"`
	Preset         string   `json:"preset"`
	Allow          []string `json:"allow,omitempty"`
	CloudProviders []string `json:"cloud_providers,omitempty"`
	IPs            []string `json:"ips"`
	Expected       string   `json:"expected"`
}

// TestParityIPLevel iterates policy_decisions.json (IP-only cases) and
// asserts that go/ressrf (WASM) and go/ressrf-static (native) agree on
// every (allowed | blocked) outcome.
func TestParityIPLevel(t *testing.T) {
	var f struct {
		Cases []ipParityCase `json:"cases"`
	}
	if err := json.Unmarshal(policyDecisionsJSON, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	ctx := context.Background()
	mismatches := 0
	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			// Build WASM-backed policy.
			wb := wasm.NewPolicyBuilder(toWasmPreset(c.Preset))
			if len(c.Allow) > 0 {
				wb.WithAllowedCIDRs(c.Allow...)
			}
			if len(c.CloudProviders) > 0 {
				wb.WithCloudProviders(c.CloudProviders...)
			}
			wp, err := wb.Build(ctx)
			if err != nil {
				t.Fatalf("wasm build: %v", err)
			}
			defer func() { _ = wp.Close(ctx) }()

			// Build native policy with identical inputs.
			nb := NewPolicyBuilder(toNativePreset(c.Preset))
			if len(c.Allow) > 0 {
				nb.WithAllowedCIDRs(c.Allow...)
			}
			if len(c.CloudProviders) > 0 {
				nb.WithCloudProviders(c.CloudProviders...)
			}
			np, err := nb.Build()
			if err != nil {
				t.Fatalf("native build: %v", err)
			}

			// Compare.
			wErr := wp.IsNetworkAllowed(ctx, c.IPs)
			nErr := np.IsNetworkAllowed(c.IPs)
			wBlocked := wErr != nil
			nBlocked := nErr != nil
			if wBlocked != nBlocked {
				mismatches++
				t.Errorf("DIVERGENCE: IPs=%v preset=%s allow=%v cloud=%v\n  wasm   blocked=%v err=%v\n  native blocked=%v err=%v",
					c.IPs, c.Preset, c.Allow, c.CloudProviders, wBlocked, wErr, nBlocked, nErr)
			}
		})
	}
	if mismatches > 0 {
		t.Errorf("\n%d IP-level divergences between WASM and native", mismatches)
	}
}

type urlParityCase struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Expected string `json:"expected"`
	Category string `json:"category,omitempty"`
}

// TestParityURLLevel runs ssrf_techniques.json URLs through both backends.
// Both use the ExternalOnly preset with no extra config — matches the
// Rust runner default. Some cases use trusted/denied suffixes which would
// need per-case URI validator config; we skip those for the parity gate
// since WASM doesn't expose per-call validator config and they're already
// covered by TestURLValidationVectors at the native level.
func TestParityURLLevel(t *testing.T) {
	var f struct {
		Cases []urlParityCase `json:"cases"`
	}
	if err := json.Unmarshal(ssrfTechniquesJSON, &f); err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := context.Background()

	wp, err := wasm.NewPolicyBuilder(wasm.PresetExternalOnly).Build(ctx)
	if err != nil {
		t.Fatalf("wasm build: %v", err)
	}
	defer func() { _ = wp.Close(ctx) }()

	np, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		t.Fatalf("native build: %v", err)
	}

	mismatches := 0
	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			wErr := wp.IsAllowed(ctx, c.URL)
			nErr := np.IsAllowed(ctx, c.URL)
			wBlocked := wErr != nil
			nBlocked := nErr != nil
			if wBlocked != nBlocked {
				mismatches++
				t.Errorf("DIVERGENCE: url=%q\n  wasm   blocked=%v err=%v\n  native blocked=%v err=%v",
					c.URL, wBlocked, wErr, nBlocked, nErr)
			}
		})
	}
	if mismatches > 0 {
		t.Errorf("\n%d URL-level divergences (out of %d) between WASM and native", mismatches, len(f.Cases))
	}
}

func toWasmPreset(s string) wasm.Preset {
	switch strings.ToLower(s) {
	case "external_only":
		return wasm.PresetExternalOnly
	case "internal_only":
		return wasm.PresetInternalOnly
	case "none":
		return wasm.PresetNone
	}
	return wasm.PresetNone
}

func toNativePreset(s string) Preset {
	switch strings.ToLower(s) {
	case "external_only":
		return PresetExternalOnly
	case "internal_only":
		return PresetInternalOnly
	case "none":
		return PresetNone
	}
	return PresetNone
}
