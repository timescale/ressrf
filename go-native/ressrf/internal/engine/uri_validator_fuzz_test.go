package engine

import "testing"

// FuzzValidateURL mirrors fuzz/fuzz_targets/fuzz_url_validator.rs. Invariants:
// (1) no panics for arbitrary input; (2) a denied URL produces a non-empty
// human-readable Error() message; (3) validation is deterministic.
func FuzzValidateURL(f *testing.F) {
	seeds := []string{
		// Allowed control cases.
		"https://example.com/", "http://example.com/path",
		"ws://example.com/socket", "wss://api.example.com/v1",
		"https://example.com:8443/path",
		"https://user:pass@example.com/",
		"http://[2606:4700:4700::1111]/",
		// Blind-spot regression seeds from tests/vectors/ssrf_techniques.json.
		"http://2130706433/",
		"http://0177.0.0.1/",
		"http://0x7f000001/",
		"http://127.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:8080/",
		"http://[::ffff:169.254.169.254]/",
		"http://user:p%40ss@169.254.169.254/",
		"http://foo%40bar@169.254.169.254/",
		"http://127.0.0.1\\@trusted.com/",
		"http:host/path", "javascript:alert(1)", "data:text/html,x",
		"http://expected.com%00.evil/",
		"http://example.com%0d%0aHost:%20x",
		"\\\\evil.com\\share", "//127.0.0.1/", "",
		// Hostname pathologies.
		"https://foo--bar.example.com/",
		"https://xn--nxasmq6b.example.com/",
		// Long path / repeated separators.
		"https://api.example.com/v1/users/123/orders/456/items",
		"https:////",
		"http://[::]/",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	policy, err := NewPolicyBuilder(PresetExternalOnly).Build()
	if err != nil {
		f.Fatalf("build policy: %v", err)
	}
	validator := NewURIValidator()

	f.Fuzz(func(t *testing.T, url string) {
		r1 := validator.ValidateURL(url, policy)
		r2 := validator.ValidateURL(url, policy)
		// Determinism: nil-ness must agree.
		if (r1 == nil) != (r2 == nil) {
			t.Fatalf("non-deterministic ValidateURL for %q: %v vs %v", url, r1, r2)
		}
		if r1 != nil {
			// A non-nil DenyReason must render to a non-empty error string.
			if r1.Error() == "" {
				t.Fatalf("empty Error() for %q", url)
			}
			// Must be one of the typed DenyReason variants — any DenyReason
			// has a Kind(); cast through the interface (no `errors.As` for
			// interfaces because every variant is a distinct concrete type).
			reason, ok := r1.(DenyReason)
			if !ok {
				t.Fatalf("ValidateURL returned non-DenyReason error for %q: %T", url, r1)
			}
			if reason.Kind().String() == "" {
				t.Fatalf("empty Kind.String() for %q", url)
			}
		}

		// Validation without a policy must also never panic.
		_ = validator.ValidateURL(url, nil)
	})
}
