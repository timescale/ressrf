package ressrfstatic

import (
	"fmt"
	"regexp"
	"strings"
)

// URLRule is a structured allow/deny rule. Either supply a Regex (matches
// against the full URL string) or some combination of Scheme/Host/Path globs.
// JSON shape mirrors the Rust UrlRule for cross-language vector compatibility.
type URLRule struct {
	// Exact scheme match (e.g. "https"). Empty matches any scheme.
	Scheme string `json:"scheme,omitempty"`
	// Host glob. `*` matches a single DNS label.
	Host string `json:"host,omitempty"`
	// Path glob. `*` matches a single segment, `**` matches any depth.
	Path string `json:"path,omitempty"`
	// Full regex against the entire URL string. When set, Scheme/Host/Path are ignored.
	Regex string `json:"regex,omitempty"`
	// When true on an allow rule, skip the IP-level policy check on a match.
	BypassIPCheck bool `json:"bypass_ip_check,omitempty"`

	// compiled regex, populated by URLRuleset.Compile.
	compiledRegex *regexp.Regexp
}

// URLRuleDecision is the outcome of evaluating a URL against a ruleset.
type URLRuleDecision int

const (
	URLRuleNoMatch          URLRuleDecision = iota // No rules matched (or none configured)
	URLRuleAllowed                                 // Allow rule matched; proceed with IP check
	URLRuleAllowedBypassIP                         // Allow rule matched with BypassIPCheck=true; skip IP check
	URLRuleDenied                                  // Deny rule matched (or have allows + no match)
)

func (d URLRuleDecision) String() string {
	switch d {
	case URLRuleNoMatch:
		return "NoMatch"
	case URLRuleAllowed:
		return "Allowed"
	case URLRuleAllowedBypassIP:
		return "AllowedBypassIP"
	case URLRuleDenied:
		return "Denied"
	}
	return "?"
}

// URLRuleset holds the allow and deny rule lists. Deny is evaluated first.
type URLRuleset struct {
	Allow []URLRule `json:"allow,omitempty"`
	Deny  []URLRule `json:"deny,omitempty"`
}

// Compile pre-builds regexes for any rules with Regex set. Must be called
// before Evaluate; calling it twice is safe (re-compiles).
func (rs *URLRuleset) Compile() error {
	if err := compileRules(rs.Deny); err != nil {
		return fmt.Errorf("ressrfstatic: deny rule: %w", err)
	}
	if err := compileRules(rs.Allow); err != nil {
		return fmt.Errorf("ressrfstatic: allow rule: %w", err)
	}
	return nil
}

func compileRules(rules []URLRule) error {
	for i := range rules {
		if rules[i].Regex == "" {
			rules[i].compiledRegex = nil
			continue
		}
		re, err := regexp.Compile(rules[i].Regex)
		if err != nil {
			return fmt.Errorf("invalid regex %q: %w", rules[i].Regex, err)
		}
		rules[i].compiledRegex = re
	}
	return nil
}

// IsEmpty reports whether the ruleset has any rules at all.
func (rs *URLRuleset) IsEmpty() bool {
	return len(rs.Allow) == 0 && len(rs.Deny) == 0
}

// Evaluate runs the ruleset against a URL string.
//
// Algorithm (ports url_rules.rs::evaluate):
//  1. Any deny match → URLRuleDenied.
//  2. No allow rules configured → URLRuleNoMatch.
//  3. First allow match → URLRuleAllowedBypassIP if BypassIPCheck else URLRuleAllowed.
//  4. Have allows, none matched → URLRuleDenied.
func (rs *URLRuleset) Evaluate(rawURL string) URLRuleDecision {
	scheme, host, path := parseURLComponents(rawURL)

	for i := range rs.Deny {
		if ruleMatches(&rs.Deny[i], rawURL, scheme, host, path) {
			return URLRuleDenied
		}
	}
	if len(rs.Allow) == 0 {
		return URLRuleNoMatch
	}
	for i := range rs.Allow {
		if ruleMatches(&rs.Allow[i], rawURL, scheme, host, path) {
			if rs.Allow[i].BypassIPCheck {
				return URLRuleAllowedBypassIP
			}
			return URLRuleAllowed
		}
	}
	return URLRuleDenied
}

func ruleMatches(r *URLRule, rawURL, scheme, host, path string) bool {
	if r.compiledRegex != nil {
		return r.compiledRegex.MatchString(rawURL)
	}
	if r.Scheme != "" && !strings.EqualFold(r.Scheme, scheme) {
		return false
	}
	if r.Host != "" && !globMatchHost(r.Host, host) {
		return false
	}
	if r.Path != "" && !globMatchPath(r.Path, path) {
		return false
	}
	return true
}

// parseURLComponents extracts (scheme, host, path) without allocating slices.
// Port of url_rules.rs::parse_url_components.
func parseURLComponents(rawURL string) (scheme, host, path string) {
	rest := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		scheme = rawURL[:idx]
		rest = rawURL[idx+3:]
	}
	slashIdx := strings.Index(rest, "/")
	var authority string
	if slashIdx < 0 {
		authority = rest
		path = "/"
	} else {
		authority = rest[:slashIdx]
		path = rest[slashIdx:]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		host = authority[at+1:]
	} else {
		host = authority
	}
	// Strip port (handle [v6]:port and v4:port).
	switch {
	case strings.HasPrefix(host, "["):
		if end := strings.Index(host, "]"); end >= 0 {
			host = host[:end+1]
		}
	default:
		if colon := strings.LastIndex(host, ":"); colon >= 0 {
			after := host[colon+1:]
			if after != "" && allASCIIDigit(after) {
				host = host[:colon]
			}
		}
	}
	return scheme, host, path
}

// globMatchHost: `*` matches exactly one DNS label.
// Port of url_rules.rs::glob_match_host.
func globMatchHost(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}
	patParts := strings.Split(pattern, ".")
	hostParts := strings.Split(host, ".")
	if len(patParts) != len(hostParts) {
		return false
	}
	for i, p := range patParts {
		if p == "*" {
			continue
		}
		if p != hostParts[i] {
			return false
		}
	}
	return true
}

// globMatchPath: `*` matches one segment, `**` matches zero or more.
// Splits on `/` and drops empty segments before matching.
// Port of url_rules.rs::glob_match_path + glob_match_segments.
func globMatchPath(pattern, path string) bool {
	pat := splitNonEmpty(pattern, "/")
	act := splitNonEmpty(path, "/")
	return globMatchSegments(pat, act)
}

func globMatchSegments(pat, p []string) bool {
	if len(pat) == 0 {
		return len(p) == 0
	}
	if pat[0] == "**" {
		// Match zero segments first…
		if globMatchSegments(pat[1:], p) {
			return true
		}
		// …or one more.
		if len(p) > 0 {
			return globMatchSegments(pat, p[1:])
		}
		return false
	}
	if len(p) == 0 {
		return false
	}
	if pat[0] == "*" || pat[0] == p[0] {
		return globMatchSegments(pat[1:], p[1:])
	}
	return false
}

func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
