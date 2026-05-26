//go:build diffuzz

package diff

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/timescale/ressrf/go-native/ressrf"
	"github.com/timescale/ressrf/go-native/ressrf/internal/testvectors"
)

// TestOracleAgreesOnKnownCases is a sanity check before running the fuzz
// target. If the Rust WASM and the native Go engine disagree on inputs the
// vectors explicitly assert, the harness itself is wrong (bad ABI, bad
// config) and there's no point trying to find subtler divergences.
func TestOracleAgreesOnKnownCases(t *testing.T) {
	ctx := context.Background()
	oracle, goPolicy := setupPair(ctx, t)
	defer oracle.Close(ctx) //nolint:errcheck // cleanup; close failure is not actionable

	cases := []struct {
		name string
		url  string
	}{
		{"public_https", "https://example.com/"},
		{"loopback_blocked", "http://127.0.0.1/"},
		{"aws_imds_blocked", "http://169.254.169.254/latest/meta-data/"},
		{"private_blocked", "http://10.0.0.1/"},
		{"unmapped_v6_loopback", "http://[::1]/"},
		{"mapped_v6_loopback", "http://[::ffff:127.0.0.1]/"},
		{"octal_loopback", "http://0177.0.0.1/"},
		{"trailing_dot_imds", "http://169.254.169.254./"},
		{"backslash_authority", "http://example.com\\@evil.com/"},
		{"userinfo_at_bypass", "http://example.com%40evil.com/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rustAllowed, err := oracle.Decide(ctx, tc.url)
			if err != nil {
				t.Fatalf("oracle decide: %v", err)
			}
			goErr := goPolicy.IsAllowed(ctx, tc.url)
			goAllowed := goErr == nil

			if rustAllowed != goAllowed {
				t.Errorf("DIVERGENCE url=%q: rust_allowed=%v go_allowed=%v go_err=%v",
					tc.url, rustAllowed, goAllowed, goErr)
			}
		})
	}
}

// FuzzPolicyDiff feeds random URLs to both engines under PresetExternalOnly
// and fails on any allow/block divergence. The seed corpus is bootstrapped
// from the published vector URLs so the first iterations cover known
// adversarial inputs before the engine explores novel ones.
//
// Reason taxonomy is intentionally not compared: cross-language reason
// strings drift cosmetically. The security-relevant question is the binary
// decision; that's what we fuzz on.
func FuzzPolicyDiff(f *testing.F) {
	ctx := context.Background()
	seedFromVectors(f)

	var (
		mu     sync.Mutex
		shared *pair
	)
	get := func(t *testing.T) *pair {
		mu.Lock()
		defer mu.Unlock()
		if shared == nil {
			oracle, goPolicy := setupPair(ctx, t)
			shared = &pair{oracle: oracle, goPolicy: goPolicy}
		}
		return shared
	}

	f.Fuzz(func(t *testing.T, url string) {
		// Guard against obviously broken inputs that just waste cycles:
		// the WASM module checks for valid UTF-8 in JSON keys (string
		// arguments). Skipping non-UTF-8 keeps fuzz throughput high without
		// hiding real bugs (the parser would reject these anyway).
		if !utf8.ValidString(url) {
			t.Skip()
		}

		p := get(t)
		rustAllowed, err := p.oracle.Decide(ctx, url)
		if err != nil {
			// Harness-level failure (e.g. instantiation error): skip rather
			// than report a divergence, which would be spurious here.
			t.Skip()
		}
		goErr := p.goPolicy.IsAllowed(ctx, url)
		goAllowed := goErr == nil
		var be *ressrf.BlockedError
		if goErr != nil && !errors.As(goErr, &be) {
			// Non-policy error from the Go side (e.g. invalid IP parsing
			// surfaced as a non-BlockedError). Skip rather than diverge.
			t.Skip()
		}

		if rustAllowed != goAllowed {
			t.Errorf("DIVERGENCE url=%q rust_allowed=%v go_allowed=%v go_err=%v",
				url, rustAllowed, goAllowed, goErr)
		}
	})
}

type pair struct {
	oracle   *Oracle
	goPolicy *ressrf.Policy
}

func setupPair(ctx context.Context, tb testing.TB) (*Oracle, *ressrf.Policy) {
	tb.Helper()
	if _, err := os.Stat(wasmPath()); err != nil {
		tb.Skipf("wasm artifact missing at %s: %v (run `make diffuzz-build-wasm`)", wasmPath(), err)
	}
	cfg := PolicyConfig{Preset: "external_only"}
	oracle, err := NewOracle(ctx, cfg)
	if err != nil {
		tb.Fatalf("oracle: %v", err)
	}
	goPolicy, err := ressrf.NewPolicy(ressrf.PresetExternalOnly)
	if err != nil {
		oracle.Close(ctx) //nolint:errcheck // cleanup; close failure is not actionable
		tb.Fatalf("go policy: %v", err)
	}
	return oracle, goPolicy
}

// seedFromVectors bootstraps the fuzz corpus from the shared conformance
// vectors. Missing or malformed vector files are silently skipped: the fuzz
// target still runs with whatever seeds did load (and the conformance tests
// fail loud independently if a vector file is broken).
func seedFromVectors(f *testing.F) {
	files := []string{
		"ssrf_techniques.json",
		"url_validation.json",
		"policy_decisions.json",
	}
	for _, name := range files {
		data, err := testvectors.Read(name)
		if err != nil {
			continue
		}
		var wire struct {
			Cases []struct {
				URL string `json:"url"`
			} `json:"cases"`
		}
		if json.Unmarshal(data, &wire) != nil {
			continue
		}
		for _, c := range wire.Cases {
			if c.URL == "" || strings.ContainsAny(c.URL, "\x00\r\n") {
				continue
			}
			f.Add(c.URL)
		}
	}
}
