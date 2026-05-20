package ressrfstatic

import "testing"

type urlRulesCase struct {
	Name     string     `json:"name"`
	Preset   string     `json:"preset,omitempty"`
	URLRules URLRuleset `json:"url_rules,omitempty"`
	URL      string     `json:"url"`
	Expected string     `json:"expected"` // "allowed" | "blocked"
	Note     string     `json:"note,omitempty"`
}

func TestURLRulesVectors(t *testing.T) {
	runVectors(t, urlRulesJSON,
		func(c urlRulesCase) string { return c.Name },
		func(t *testing.T, c urlRulesCase) {
			rs := c.URLRules
			if err := rs.Compile(); err != nil {
				t.Fatalf("compile: %v", err)
			}
			got := rs.Evaluate(c.URL)
			switch c.Expected {
			case "allowed":
				// Allowed, AllowedBypassIP, NoMatch all pass at this layer
				// (the IP-level check would decide further).
				if got == URLRuleDenied {
					t.Errorf("expected allowed (or no-match), got Denied")
				}
			case "blocked":
				if got != URLRuleDenied {
					t.Errorf("expected Denied, got %v", got)
				}
			default:
				t.Fatalf("unknown expected %q", c.Expected)
			}
		})
}

func TestHostGlobUnit(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "foo.bar.example.com", false},
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "API.example.com", true},
		{"*.example.com", "example.com", false},
		{"*", "anything", true},
	}
	for _, c := range cases {
		t.Run(c.pattern+"_vs_"+c.host, func(t *testing.T) {
			if got := globMatchHost(c.pattern, c.host); got != c.want {
				t.Errorf("globMatchHost(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
			}
		})
	}
}

func TestPathGlobUnit(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/v1/charges", "/v1/charges", true},
		{"/v1/*", "/v1/charges", true},
		{"/v1/*", "/v1/charges/123", false},
		{"/v1/**", "/v1/charges", true},
		{"/v1/**", "/v1/charges/123", true},
		{"/api/**", "/api", true}, // ** matches zero or more
		{"/v1/*", "/v2/charges", false},
	}
	for _, c := range cases {
		t.Run(c.pattern+"_vs_"+c.path, func(t *testing.T) {
			if got := globMatchPath(c.pattern, c.path); got != c.want {
				t.Errorf("globMatchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
			}
		})
	}
}

func TestRegexRuleInvalid(t *testing.T) {
	rs := URLRuleset{Deny: []URLRule{{Regex: "[unclosed"}}}
	if err := rs.Compile(); err == nil {
		t.Errorf("expected compile error for invalid regex")
	}
}
