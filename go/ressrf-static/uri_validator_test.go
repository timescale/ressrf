package ressrfstatic

import "testing"

// urlValidationCase mirrors the cases[] entries in url_validation.json.
type urlValidationCase struct {
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	Expected        string   `json:"expected"` // "allowed" | "blocked"
	ReasonType      string   `json:"reason_type,omitempty"`
	DeniedSuffixes  []string `json:"denied_suffixes,omitempty"`
	TrustedSuffixes []string `json:"trusted_suffixes,omitempty"`
	Note            string   `json:"note,omitempty"`
}

func TestURLValidationVectors(t *testing.T) {
	policy, err := NewExternalOnlyPolicy()
	if err != nil {
		t.Fatalf("build external_only policy: %v", err)
	}

	runVectors(t, urlValidationJSON,
		func(c urlValidationCase) string { return c.Name },
		func(t *testing.T, c urlValidationCase) {
			v := NewURIValidator()
			if len(c.DeniedSuffixes) > 0 {
				v.AddDeniedSuffixes(c.DeniedSuffixes...)
			}
			if len(c.TrustedSuffixes) > 0 {
				v.AddTrustedSuffixes(c.TrustedSuffixes...)
			}
			err := v.ValidateURL(c.URL, policy)
			switch c.Expected {
			case "allowed":
				if err != nil {
					t.Errorf("expected allowed, got %v", err)
				}
			case "blocked":
				if err == nil {
					t.Errorf("expected blocked (%s), got allowed", c.ReasonType)
					return
				}
				// reason_type is metadata: the Rust conformance runner
				// (crates/ressrf-core/tests/test_vectors.rs) only asserts on
				// err presence, not the reason class. Several URLs match
				// multiple deny rules (e.g. userinfo bypass + bare IP); which
				// one fires first depends on pipeline order. Log mismatches
				// for visibility without failing.
				if c.ReasonType != "" {
					if be, ok := err.(*BlockedError); ok && string(be.Reason) != c.ReasonType {
						t.Logf("reason mismatch (informational): got %q, vector annotated %q", be.Reason, c.ReasonType)
					}
				}
			default:
				t.Fatalf("unknown expected value %q", c.Expected)
			}
		})
}

// TestURIValidatorUnitSmokes covers a handful of edge cases that are
// finicky and easier to assert in code than via vector data.
func TestURIValidatorUnitSmokes(t *testing.T) {
	policy, err := NewExternalOnlyPolicy()
	if err != nil {
		t.Fatal(err)
	}
	v := NewURIValidator()
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"javascript_pseudo_scheme", "javascript:alert(1)", true},
		{"data_pseudo_scheme", "data:text/html,<script>", true},
		{"file_scheme", "file:///etc/passwd", true},
		{"backslash_normalization_allowed", `http://example.com\@evil.com/`, false}, // backslash → /, so host=example.com (BS-5 defence: the actual connection goes to example.com, evil.com becomes part of the path)
		{"unc_path", `\\evilhost\share`, true},
		{"trailing_dot_ok", "http://example.com./", false},
		{"ipv6_loopback_bracket", "http://[::1]:8080/", true},
		{"crlf_in_url", "http://example.com/\r\nHost: evil.com", true},
		{"percent_encoded_nul_in_host", "http://example.com%00.evil.com/", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := v.ValidateURL(c.url, policy)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateURL(%q) err=%v, wantErr=%v", c.url, err, c.wantErr)
			}
		})
	}
}
