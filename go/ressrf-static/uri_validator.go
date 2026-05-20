package ressrfstatic

import (
	"strings"
)

// defaultAllowedSchemes is the URI scheme allowlist. Mirrors
// crates/ressrf-core/src/uri_validator.rs::DEFAULT_ALLOWED_SCHEMES.
var defaultAllowedSchemes = []string{"http", "https", "ws", "wss"}

// URIValidator performs string-only URL checks: scheme allowlist, hostname
// shape, bare-IP detection, userinfo bypass resistance, and domain suffix
// matching. It does NOT do DNS or open connections.
//
// Port of crates/ressrf-core/src/uri_validator.rs::UriValidator.
type URIValidator struct {
	allowedSchemes           []string
	trustedDomainSuffixes    []string // lower-cased, leading dot trimmed in matcher
	deniedDomainSuffixes     []string // lower-cased
	rejectDoubleDashHostname bool
}

// NewURIValidator returns a validator with the default scheme allowlist
// (http, https, ws, wss), no domain suffixes configured, and double-dash
// rejection enabled (with punycode xn-- exemption).
func NewURIValidator() *URIValidator {
	schemes := make([]string, len(defaultAllowedSchemes))
	copy(schemes, defaultAllowedSchemes)
	return &URIValidator{
		allowedSchemes:           schemes,
		rejectDoubleDashHostname: true,
	}
}

// AddTrustedSuffixes adds domain suffixes to the trusted-host allowlist.
// Suffixes are normalized to lowercase; a leading dot is allowed and ignored.
func (v *URIValidator) AddTrustedSuffixes(suffixes ...string) *URIValidator {
	for _, s := range suffixes {
		v.trustedDomainSuffixes = append(v.trustedDomainSuffixes, strings.ToLower(s))
	}
	return v
}

// AddDeniedSuffixes adds domain suffixes to the deny list (e.g. ".internal",
// ".svc.cluster.local"). Lowercased on insert.
func (v *URIValidator) AddDeniedSuffixes(suffixes ...string) *URIValidator {
	for _, s := range suffixes {
		v.deniedDomainSuffixes = append(v.deniedDomainSuffixes, strings.ToLower(s))
	}
	return v
}

// SetRejectDoubleDash toggles the hostname `--` rejection. Punycode labels
// starting with `xn--` are always allowed regardless.
func (v *URIValidator) SetRejectDoubleDash(reject bool) *URIValidator {
	v.rejectDoubleDashHostname = reject
	return v
}

// ValidateURL runs the full string-only URL validation pipeline. If policy is
// non-nil, bare-IP hosts are checked against policy.IsNetworkAllowed before
// any further validation (so an IMDS-IP URL is rejected even when no domain
// rules would catch it).
//
// Steps (matching the Rust port lines 86-192):
//  1. Parse URL parts (reject UNC, embedded NUL/CR/LF, normalize backslash).
//  2. Scheme must be present and in the allowlist (rejects javascript:,
//     data:, file:, ftp:, scheme-less inputs).
//  3. Strip trailing dot from host; empty after strip → reject.
//  4. Reject ambiguous IPv4 encodings (octal/hex/decimal/shorthand).
//  5. If host is a bare IP literal and policy is provided, validate the IP.
//  6. Reject userinfo bypass attempts (raw @ + %40 in authority).
//  7. Hostname hardening: reject non-punycode `--`, denied suffixes, then
//     enforce trusted-suffix allowlist if configured.
func (v *URIValidator) ValidateURL(rawURL string, policy *Policy) error {
	rawURL = strings.TrimSpace(rawURL)

	parts, err := parseURLParts(rawURL)
	if err != nil {
		return err
	}

	// Step 2: scheme allowlist.
	if parts.scheme != "" {
		schemeLower := strings.ToLower(parts.scheme)
		if !containsString(v.allowedSchemes, schemeLower) {
			return &BlockedError{Reason: ReasonSchemeNotAllowed, URL: rawURL, DetailText: schemeLower}
		}
	} else {
		if pseudo := pseudoScheme(rawURL); pseudo != "" {
			return &BlockedError{Reason: ReasonSchemeNotAllowed, URL: rawURL, DetailText: strings.ToLower(pseudo)}
		}
		return &BlockedError{Reason: ReasonSchemeRequired, URL: rawURL}
	}

	// Step 3: strip trailing dot from host.
	hostNormalized := strings.TrimRight(parts.host, ".")
	if hostNormalized == "" {
		return &BlockedError{Reason: ReasonURLParseError, URL: rawURL, DetailText: "empty host after stripping trailing dot"}
	}

	// Step 4: ambiguous IP encoding.
	if IsAmbiguousIP(hostNormalized) {
		return &BlockedError{Reason: ReasonAmbiguousIPEncoding, URL: rawURL, Host: hostNormalized, DetailText: "non-canonical IPv4 (octal/hex/decimal/shorthand)"}
	}

	// Step 5: bare IP literal → policy check.
	isIPLit := IsIPLiteral(hostNormalized)
	if isIPLit && policy != nil {
		ip := hostNormalized
		if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
			ip = ip[1 : len(ip)-1]
		}
		if err := policy.IsNetworkAllowed([]string{ip}); err != nil {
			if be, ok := err.(*BlockedError); ok {
				// Reclassify so audit shows "bare IP before scheme" rather than
				// the lower-level CIDR-deny reason.
				return &BlockedError{Reason: ReasonBareIPDeniedBeforeScheme, URL: rawURL, IP: be.IP}
			}
			return err
		}
	}

	// Step 6: userinfo bypass.
	if hasUserinfoBypass(rawURL) {
		return &BlockedError{Reason: ReasonUserinfoBypassAttempt, URL: rawURL}
	}

	// Step 7: hostname hardening.
	hostLower := strings.ToLower(hostNormalized)

	if v.rejectDoubleDashHostname && strings.Contains(hostLower, "--") {
		for _, label := range strings.Split(hostLower, ".") {
			if strings.Contains(label, "--") && !strings.HasPrefix(label, "xn--") {
				return &BlockedError{Reason: ReasonHostnameInvalid, URL: rawURL, Host: hostLower, DetailText: "hostname contains '--' (non-punycode)"}
			}
		}
	}

	for _, suffix := range v.deniedDomainSuffixes {
		if domainMatchesSuffix(hostLower, suffix) {
			return &BlockedError{Reason: ReasonDomainSuffixDenied, URL: rawURL, Host: hostLower, Suffix: suffix}
		}
	}

	if len(v.trustedDomainSuffixes) > 0 && !isIPLit {
		match := false
		for _, suffix := range v.trustedDomainSuffixes {
			if domainMatchesSuffix(hostLower, suffix) {
				match = true
				break
			}
		}
		if !match {
			return &BlockedError{Reason: ReasonDomainNotInAllowList, URL: rawURL, Host: hostLower}
		}
	}

	return nil
}

// IsTrustedDomain reports whether host matches any configured trusted suffix.
// Convenience for callers that want to bypass policy on known-safe domains.
func (v *URIValidator) IsTrustedDomain(host string) bool {
	host = strings.ToLower(strings.TrimRight(host, "."))
	for _, suffix := range v.trustedDomainSuffixes {
		if domainMatchesSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// --- URL parsing ---

type urlParts struct {
	scheme string
	host   string
}

// parseURLParts extracts scheme and host without depending on net/url's
// liberal RFC 3986/WHATWG handling. Port of
// crates/ressrf-core/src/uri_validator.rs::parse_url_parts.
func parseURLParts(s string) (urlParts, error) {
	if s == "" {
		return urlParts{}, &BlockedError{Reason: ReasonURLParseError, DetailText: "empty URL"}
	}
	if strings.HasPrefix(s, `\\`) {
		return urlParts{}, &BlockedError{Reason: ReasonURLParseError, DetailText: "UNC-style path not allowed"}
	}
	if hasProhibitedControlChars(s) {
		return urlParts{}, &BlockedError{Reason: ReasonHostnameInvalid, DetailText: "URL contains prohibited control characters (NUL/CR/LF)"}
	}

	var scheme, rest string
	if idx := strings.Index(s, "://"); idx >= 0 {
		scheme = s[:idx]
		rest = strings.ReplaceAll(s[idx+3:], `\`, "/")
	} else {
		rest = strings.ReplaceAll(s, `\`, "/")
	}

	authority := rest
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(authority, sep); i >= 0 {
			authority = authority[:i]
		}
	}

	hostPart := authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		hostPart = authority[at+1:]
	}

	var host string
	switch {
	case strings.HasPrefix(hostPart, "["):
		if end := strings.Index(hostPart, "]"); end >= 0 {
			host = hostPart[:end+1]
		} else {
			host = hostPart
		}
	default:
		if colon := strings.LastIndex(hostPart, ":"); colon >= 0 {
			after := hostPart[colon+1:]
			if after != "" && allASCIIDigit(after) {
				host = hostPart[:colon]
			} else {
				host = hostPart
			}
		} else {
			host = hostPart
		}
	}

	if host == "" {
		return urlParts{}, &BlockedError{Reason: ReasonURLParseError, DetailText: "empty host"}
	}
	if hostHasProhibitedChars(host) {
		return urlParts{}, &BlockedError{Reason: ReasonHostnameInvalid, DetailText: "host contains prohibited control characters (NUL/CR/LF)"}
	}

	return urlParts{scheme: scheme, host: host}, nil
}

// hasProhibitedControlChars detects raw NUL/CR/LF anywhere in the input.
// Port of has_prohibited_control_chars.
func hasProhibitedControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == 0 || b == '\r' || b == '\n' {
			return true
		}
	}
	return false
}

// hostHasProhibitedChars combines raw-byte and percent-encoded forms.
func hostHasProhibitedChars(host string) bool {
	if hasProhibitedControlChars(host) {
		return true
	}
	low := strings.ToLower(host)
	return strings.Contains(low, "%00") || strings.Contains(low, "%0d") || strings.Contains(low, "%0a")
}

// pseudoScheme returns the prefix before the first `:` when the URL has a
// `:` before any `/` but no `://`. Used to reject javascript:, data:,
// file://host (without `//`), etc. Port of pseudo_scheme.
func pseudoScheme(rawURL string) string {
	colon := strings.Index(rawURL, ":")
	if colon < 0 {
		return ""
	}
	slash := strings.Index(rawURL, "/")
	if slash >= 0 && slash < colon {
		return ""
	}
	candidate := rawURL[:colon]
	if candidate == "" {
		return ""
	}
	if !isASCIIAlpha(candidate[0]) {
		return ""
	}
	for i := 0; i < len(candidate); i++ {
		b := candidate[i]
		ok := isASCIIAlpha(b) || (b >= '0' && b <= '9') || b == '+' || b == '-' || b == '.'
		if !ok {
			return ""
		}
	}
	return candidate
}

// hasUserinfoBypass detects URL-encoded `@` (`%40`) used to confuse parsers
// about where the authority ends. Port of has_userinfo_bypass.
func hasUserinfoBypass(rawURL string) bool {
	rest := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest = rawURL[idx+3:]
	}
	authority := rest
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(authority, sep); i >= 0 {
			authority = authority[:i]
		}
	}

	if strings.Contains(authority, "@") && strings.Contains(authority, "%40") {
		return true
	}
	if pos := strings.Index(authority, "%40"); pos >= 0 {
		after := authority[pos+3:]
		afterHost := after
		if at := strings.LastIndex(after, "@"); at >= 0 {
			afterHost = after[at+1:]
		}
		if strings.ContainsAny(afterHost, ".:") {
			return true
		}
	}
	return false
}

// domainMatchesSuffix is boundary-aware: "api.example.com" matches
// "example.com" / ".example.com" but "notexample.com" does not.
// Port of domain_matches_suffix.
func domainMatchesSuffix(host, suffix string) bool {
	host = strings.TrimRight(host, ".")
	suffix = strings.TrimRight(suffix, ".")
	if strings.HasPrefix(suffix, ".") {
		suffix = suffix[1:]
	}
	if host == suffix {
		return true
	}
	if strings.HasSuffix(host, suffix) {
		prefixEnd := len(host) - len(suffix)
		if prefixEnd > 0 && host[prefixEnd-1] == '.' {
			return true
		}
	}
	return false
}

// --- helpers ---

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
