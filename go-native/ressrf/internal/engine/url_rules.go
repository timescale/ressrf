package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// URLRule is the compiled form of a single URL allow/deny rule. The public
// ressrf.URLRule type is converted into this via CompileURLRule before being
// added to a Ruleset.
type URLRule struct {
	Scheme        string
	HostPattern   string
	PathPattern   string
	Regex         *regexp.Regexp
	BypassIPCheck bool
}

// CompileURLRule compiles regex (if any) and pre-lowercases pattern strings
// so the hot path doesn't allocate.
func CompileURLRule(scheme, host, path, regex string, bypassIP bool) (URLRule, error) {
	rule := URLRule{
		Scheme:        strings.ToLower(scheme),
		HostPattern:   strings.ToLower(host),
		PathPattern:   path,
		BypassIPCheck: bypassIP,
	}
	if regex != "" {
		re, err := regexp.Compile(regex)
		if err != nil {
			return URLRule{}, fmt.Errorf("invalid URL rule regex: %w", err)
		}
		rule.Regex = re
	}
	return rule, nil
}

// URLRuleDecision is the outcome of evaluating a ruleset against a URL.
type URLRuleDecision uint8

const (
	URLNoMatch URLRuleDecision = iota
	URLAllowed
	URLAllowedBypassIP
	URLDenied
)

// URLRuleset holds the allow/deny lists. Deny rules are evaluated first; if
// any allow rule is present, a URL must match an allow rule or it is denied.
type URLRuleset struct {
	Allow []URLRule
	Deny  []URLRule
}

func (r *URLRuleset) IsEmpty() bool { return len(r.Allow) == 0 && len(r.Deny) == 0 }

// Evaluate runs the deny-then-allow precedence chain described in
// crates/ressrf-core/src/url_rules.rs::evaluate.
func (r *URLRuleset) Evaluate(url string) URLRuleDecision {
	scheme, host, path := splitURLComponents(url)
	for _, rule := range r.Deny {
		if rule.matches(url, scheme, host, path) {
			return URLDenied
		}
	}
	if len(r.Allow) == 0 {
		return URLNoMatch
	}
	for _, rule := range r.Allow {
		if rule.matches(url, scheme, host, path) {
			if rule.BypassIPCheck {
				return URLAllowedBypassIP
			}
			return URLAllowed
		}
	}
	return URLDenied
}

func (rule URLRule) matches(url, scheme, host, path string) bool {
	if rule.Regex != nil {
		return rule.Regex.MatchString(url)
	}
	if rule.Scheme != "" && !strings.EqualFold(rule.Scheme, scheme) {
		return false
	}
	if rule.HostPattern != "" && !globMatchHost(rule.HostPattern, host) {
		return false
	}
	if rule.PathPattern != "" && !globMatchPath(rule.PathPattern, path) {
		return false
	}
	return true
}

// splitURLComponents extracts scheme / host / path from a URL string without
// allocating beyond substrings. Mirrors crates/ressrf-core/src/url_rules.rs::parse_url_components.
func splitURLComponents(url string) (scheme, host, path string) {
	rest := url
	if before, after, ok := strings.Cut(url, "://"); ok {
		scheme = before
		rest = after
	}
	slashIdx := strings.IndexByte(rest, '/')
	var authority string
	if slashIdx < 0 {
		authority = rest
		path = "/"
	} else {
		authority = rest[:slashIdx]
		path = rest[slashIdx:]
	}
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		authority = authority[at+1:]
	}
	host = authority
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end >= 0 {
			host = host[:end+1]
		}
	} else if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		after := host[colon+1:]
		if after != "" && allDigits(after) {
			host = host[:colon]
		}
	}
	return scheme, host, path
}

// globMatchHost matches a host pattern where `*` matches a single DNS label.
// Comparison is case-insensitive. Pattern parts and host parts must be the
// same length (`*.example.com` does not match `a.b.example.com`).
func globMatchHost(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}
	pParts := strings.Split(pattern, ".")
	hParts := strings.Split(host, ".")
	if len(pParts) != len(hParts) {
		return false
	}
	for i := range pParts {
		if pParts[i] == "*" {
			continue
		}
		if pParts[i] != hParts[i] {
			return false
		}
	}
	return true
}

// globMatchPath matches a path pattern where `*` matches one segment and `**`
// matches zero or more segments.
func globMatchPath(pattern, path string) bool {
	patternSegs := splitNonEmpty(pattern, '/')
	pathSegs := splitNonEmpty(path, '/')
	return globMatchSegments(patternSegs, pathSegs)
}

func splitNonEmpty(s string, sep byte) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, strings.Count(s, string(sep))+1)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func globMatchSegments(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == "**" {
		// `**` may consume zero or more segments.
		if globMatchSegments(pattern[1:], path) {
			return true
		}
		if len(path) > 0 {
			return globMatchSegments(pattern, path[1:])
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	if pattern[0] == "*" || pattern[0] == path[0] {
		return globMatchSegments(pattern[1:], path[1:])
	}
	return false
}
