package ressrfstatic

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// All conformance vectors are embedded once here so individual *_test.go
// files don't each repeat the //go:embed lines. New vector files should be
// added here and referenced by feature-specific test files.
//
// The source-of-truth is repo-root tests/vectors/; ./testdata/vectors/ is a
// copy refreshed via go generate so //go:embed (which can't escape the module)
// can pick them up.

//go:embed testdata/vectors/url_validation.json
var urlValidationJSON []byte

//go:embed testdata/vectors/url_rules.json
var urlRulesJSON []byte

//go:embed testdata/vectors/policy_decisions.json
var policyDecisionsJSON []byte

//go:embed testdata/vectors/redirect_chains.json
var redirectChainsJSON []byte

//go:embed testdata/vectors/ssrf_techniques.json
var ssrfTechniquesJSON []byte

//go:embed testdata/vectors/audit_events.json
var auditEventsJSON []byte

// vectorFile is the common shape across all vector JSON files. Per-feature
// case types are passed as a type parameter so the loader stays generic.
type vectorFile[V any] struct {
	Description string `json:"description,omitempty"`
	Schema      string `json:"schema,omitempty"`
	Cases       []V    `json:"cases"`
}

// runVectors decodes the given JSON bytes into a list of cases and invokes
// fn once per case as a t.Run subtest. The case is passed by pointer so the
// callback can read fields without copying large structs.
func runVectors[V any](t *testing.T, raw []byte, nameOf func(V) string, fn func(*testing.T, V)) {
	t.Helper()
	var f vectorFile[V]
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vector file: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("vector file has zero cases")
	}
	for i, c := range f.Cases {
		name := nameOf(c)
		if name == "" {
			name = fmt.Sprintf("case_%03d", i)
		}
		name = sanitizeSubtestName(name)
		t.Run(name, func(t *testing.T) { fn(t, c) })
	}
}

// sanitizeSubtestName produces a t.Run-safe identifier. Go truncates names
// at slashes, so we replace path separators with underscores; also cap length
// to keep test output readable.
func sanitizeSubtestName(s string) string {
	if s == "" {
		return "anonymous"
	}
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}
