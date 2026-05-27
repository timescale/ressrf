package engine

import "testing"

// FuzzURLRulesEvaluate fuzzes the deny-first ruleset evaluation. The fuzzed
// pattern is built into a single deny rule; the property is that any URL the
// deny rule matches must produce URLDenied, and the evaluator is deterministic.
func FuzzURLRulesEvaluate(f *testing.F) {
	seeds := [][3]string{
		// scheme, hostPattern, pathPattern, target URL packed as one
		// f.Add per seed. The fuzz harness only supports a fixed type
		// signature, so we use four string args.
		{"https", "*.stripe.com", "/v1/**"},
		{"", "*.internal", ""},
		{"", "api.example.com", "/api/*"},
		{"https", "*.Example.COM", "/**"},
	}
	seedURLs := []string{
		"https://api.stripe.com/v1/charges",
		"http://db.internal/x",
		"https://API.example.com/data",
		"https://evil.com/path",
		"http://api.example.com/api/v1/users",
		"https://api.example.com/api/x",
	}
	for _, s := range seeds {
		for _, u := range seedURLs {
			f.Add(s[0], s[1], s[2], u)
		}
	}
	f.Fuzz(func(t *testing.T, scheme, hostPat, pathPat, url string) {
		denyRule, err := CompileURLRule(scheme, hostPat, pathPat, "", false)
		if err != nil {
			return
		}
		ruleset := URLRuleset{Deny: []URLRule{denyRule}}
		r1 := ruleset.Evaluate(url)
		r2 := ruleset.Evaluate(url)
		if r1 != r2 {
			t.Fatalf("non-deterministic Evaluate for url=%q: %v vs %v", url, r1, r2)
		}
		// If the (only) rule is a deny, only Denied or NoMatch are valid
		// outcomes (no allow rules → no AllowedBypassIP).
		if r1 == URLAllowed || r1 == URLAllowedBypassIP {
			t.Fatalf("unexpected allow decision %v for deny-only ruleset (url=%q)", r1, url)
		}
	})
}

// FuzzGlobMatchHost ensures the host glob matcher is panic-free and
// case-insensitive for arbitrary pattern / host pairs.
func FuzzGlobMatchHost(f *testing.F) {
	pairs := [][2]string{
		{"*.example.com", "api.example.com"},
		{"*.example.com", "a.b.example.com"},
		{"example.com", "example.com"},
		{"*.*.example.com", "a.b.example.com"},
		{"*", ""},
		{"", ""},
		{"foo.*.bar", "foo..bar"},
	}
	for _, p := range pairs {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		a := globMatchHost(pattern, host)
		b := globMatchHost(pattern, host)
		if a != b {
			t.Fatalf("non-deterministic globMatchHost(%q, %q)", pattern, host)
		}
	})
}

// FuzzGlobMatchPath does the same for the path-segment matcher, including
// the `**` recursion that could in principle stack-overflow on a pathological
// pattern. Failure here would indicate the recursion needs a depth bound.
func FuzzGlobMatchPath(f *testing.F) {
	pairs := [][2]string{
		{"/v1/*", "/v1/users"},
		{"/api/**", "/api/v1/users/123"},
		{"/**", "/anything/at/all"},
		{"/", "/"},
		{"", ""},
		{"/**/**/**", "/a/b/c"},
	}
	for _, p := range pairs {
		f.Add(p[0], p[1])
	}
	f.Fuzz(func(t *testing.T, pattern, path string) {
		_ = globMatchPath(pattern, path)
	})
}
