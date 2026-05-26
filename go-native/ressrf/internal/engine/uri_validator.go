package engine

import (
	"net/netip"
	"slices"
	"strings"
)

// defaultAllowedSchemes mirrors crates/ressrf-core/src/uri_validator.rs.
var defaultAllowedSchemes = []string{"http", "https", "ws", "wss"}

// URIValidator performs string-only URL validation (no DNS, no I/O). It is
// embedded in Policy and shares the policy's allow / deny CIDR sets when a
// caller needs the bare-IP-before-scheme check.
type URIValidator struct {
	allowedSchemes        []string
	allowListSuffixes     []string
	deniedSuffixes        []string
	rejectDoubleDashHosts bool
}

func NewURIValidator() *URIValidator {
	return &URIValidator{
		allowedSchemes:        append([]string(nil), defaultAllowedSchemes...),
		rejectDoubleDashHosts: true,
	}
}

func (v *URIValidator) AddDeniedSuffixes(suffixes []string) {
	for _, s := range suffixes {
		v.deniedSuffixes = append(v.deniedSuffixes, strings.ToLower(s))
	}
}

// AddDomainAllowList registers suffixes for allow-list mode: once any suffix
// is registered, non-IP hosts not matching one of the registered suffixes are
// rejected with DomainNotInAllowList. The name says what the call does;
// callers can't accidentally enable this mode by reaching for what looks like
// an additive "trusted" knob.
func (v *URIValidator) AddDomainAllowList(suffixes []string) {
	for _, s := range suffixes {
		v.allowListSuffixes = append(v.allowListSuffixes, strings.ToLower(s))
	}
}

// ValidateURL runs the full BS-1 through BS-6 chain from the Rust core.
// Returns nil on success or a DenyReason (implementing error) on rejection.
func (v *URIValidator) ValidateURL(rawURL string, policy *Policy) error {
	if r := v.validateURL(rawURL, policy); r != nil {
		return r
	}
	return nil
}

// validateURL drives ValidateURL and the IsRequestAllowed hot path. Returns
// a typed DenyReason (one of the structs in deny_reasons.go) or nil.
// Steps mirror crates/ressrf-core/src/uri_validator.rs::validate_url.
func (v *URIValidator) validateURL(rawURL string, policy *Policy) DenyReason {
	url := strings.TrimSpace(rawURL)
	parts, denyReason := parseURLParts(url)
	if denyReason != nil {
		return denyReason
	}

	// 2. Scheme validation.
	if parts.scheme != "" {
		schemeLower := strings.ToLower(parts.scheme)
		if !contains(v.allowedSchemes, schemeLower) {
			return &SchemeNotAllowed{Scheme: schemeLower}
		}
	} else {
		if pseudo := pseudoScheme(url); pseudo != "" {
			return &SchemeNotAllowed{Scheme: strings.ToLower(pseudo)}
		}
		return &SchemeRequired{}
	}

	// 3. Trailing dot strip.
	hostNormalized := strings.TrimRight(parts.host, ".")
	if hostNormalized == "" {
		return &UrlParseError{Detail: "empty host after stripping trailing dot"}
	}

	// 4. Ambiguous IP encoding.
	if IsAmbiguousIP(hostNormalized) {
		return &AmbiguousIPEncoding{
			Host: hostNormalized,
			Form: "non-canonical IPv4 (octal/hex/decimal/shorthand)",
		}
	}

	// 5. Bare IP -> evaluate against policy before anything else.
	if IsIPLiteral(hostNormalized) && policy != nil {
		ip, perr := parseHostAsIP(hostNormalized)
		if perr != nil {
			return &UrlParseError{Detail: perr.Error()}
		}
		if inner := policy.isNetworkAllowedIPs([]netip.Addr{ip}); inner != nil {
			switch inner.(type) {
			case *InDenyCIDR, *NotInAllowList:
				return &BareIPDeniedBeforeScheme{Host: ip.String()}
			}
			return inner
		}
	}

	// 6. Userinfo bypass via percent-encoded @.
	if hasUserinfoBypass(url) {
		return &UserinfoBypassAttempt{}
	}

	// 7. Hostname rules.
	hostLower := strings.ToLower(hostNormalized)
	if v.rejectDoubleDashHosts && strings.Contains(hostLower, "--") {
		bad := false
		for label := range strings.SplitSeq(hostLower, ".") {
			if strings.Contains(label, "--") && !strings.HasPrefix(label, "xn--") {
				bad = true
				break
			}
		}
		if bad {
			return &HostnameInvalid{Detail: "hostname contains '--' (non-punycode)"}
		}
	}

	for _, suffix := range v.deniedSuffixes {
		if domainMatchesSuffix(hostLower, suffix) {
			return &DomainSuffixDenied{Host: hostLower, Suffix: suffix}
		}
	}

	if len(v.allowListSuffixes) > 0 && !IsIPLiteral(hostNormalized) {
		matched := false
		for _, suffix := range v.allowListSuffixes {
			if domainMatchesSuffix(hostLower, suffix) {
				matched = true
				break
			}
		}
		if !matched {
			return &DomainNotInAllowList{Host: hostLower}
		}
	}

	return nil
}

type urlParts struct {
	scheme string
	host   string
}

func parseURLParts(url string) (urlParts, DenyReason) {
	if url == "" {
		return urlParts{}, &UrlParseError{Detail: "empty URL"}
	}
	// BS-6: reject UNC-style \\host\share.
	if strings.HasPrefix(url, "\\\\") {
		return urlParts{}, &UrlParseError{Detail: "UNC-style path not allowed"}
	}
	// BS-3: reject NUL/CR/LF early so we don't accidentally let them through.
	if hasProhibitedControl(url) {
		return urlParts{}, &HostnameInvalid{Detail: "URL contains prohibited control characters (NUL/CR/LF)"}
	}

	var scheme, rest string
	if before, after, ok := strings.Cut(url, "://"); ok {
		scheme = before
		rest = strings.ReplaceAll(after, "\\", "/")
	} else {
		rest = strings.ReplaceAll(url, "\\", "/")
	}

	authority := rest
	if i := strings.IndexByte(authority, '/'); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.IndexByte(authority, '?'); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.IndexByte(authority, '#'); i >= 0 {
		authority = authority[:i]
	}

	hostPart := authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		hostPart = authority[at+1:]
	}

	var host string
	if strings.HasPrefix(hostPart, "[") {
		if end := strings.IndexByte(hostPart, ']'); end >= 0 {
			host = hostPart[:end+1]
		} else {
			host = hostPart
		}
	} else if colon := strings.LastIndexByte(hostPart, ':'); colon >= 0 {
		after := hostPart[colon+1:]
		if after != "" && allDigits(after) {
			host = hostPart[:colon]
		} else {
			host = hostPart
		}
	} else {
		host = hostPart
	}

	if host == "" {
		return urlParts{}, &UrlParseError{Detail: "empty host"}
	}

	if hostHasProhibitedChars(host) {
		return urlParts{}, &HostnameInvalid{Detail: "host contains prohibited control characters (NUL/CR/LF)"}
	}

	return urlParts{scheme: scheme, host: host}, nil
}

func hasProhibitedControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0 || c == '\r' || c == '\n' {
			return true
		}
	}
	return false
}

func hostHasProhibitedChars(host string) bool {
	if hasProhibitedControl(host) {
		return true
	}
	lower := strings.ToLower(host)
	return strings.Contains(lower, "%00") || strings.Contains(lower, "%0d") || strings.Contains(lower, "%0a")
}

// pseudoScheme returns the scheme prefix of a URL that has `scheme:` but no
// `://`. Used to surface BS-2 rejections (javascript:, data:, http:host/path).
func pseudoScheme(url string) string {
	colon := strings.IndexByte(url, ':')
	if colon < 0 {
		return ""
	}
	if slash := strings.IndexByte(url, '/'); slash >= 0 && slash < colon {
		return ""
	}
	candidate := url[:colon]
	if candidate == "" {
		return ""
	}
	if !isSchemeStart(candidate[0]) {
		return ""
	}
	for i := 0; i < len(candidate); i++ {
		if !isSchemeByte(candidate[i]) {
			return ""
		}
	}
	return candidate
}

// isSchemeStart reports whether b is a valid first character for an RFC 3986
// URI scheme: ALPHA only.
func isSchemeStart(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	}
	return false
}

// isSchemeByte reports whether b may appear inside an RFC 3986 URI scheme:
// ALPHA / DIGIT / "+" / "-" / ".".
func isSchemeByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '+', b == '-', b == '.':
		return true
	}
	return false
}

// hasUserinfoBypass mirrors the Rust detector for percent-encoded @ in the
// authority that could confuse downstream URL parsers.
func hasUserinfoBypass(url string) bool {
	rest := url
	if _, after, ok := strings.Cut(url, "://"); ok {
		rest = after
	}
	authority := rest
	if i := strings.IndexByte(authority, '/'); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.IndexByte(authority, '?'); i >= 0 {
		authority = authority[:i]
	}
	if i := strings.IndexByte(authority, '#'); i >= 0 {
		authority = authority[:i]
	}
	if strings.Contains(authority, "@") && strings.Contains(authority, "%40") {
		return true
	}
	if _, after, ok := strings.Cut(authority, "%40"); ok {
		after := after
		if at := strings.LastIndexByte(after, '@'); at >= 0 {
			after = after[at+1:]
		}
		if strings.ContainsAny(after, ".:") {
			return true
		}
	}
	return false
}

// domainMatchesSuffix does boundary-aware suffix matching. `api.example.com`
// matches suffix `example.com` but `notexample.com` does not.
func domainMatchesSuffix(host, suffix string) bool {
	host = strings.TrimRight(host, ".")
	suffix = strings.TrimRight(suffix, ".")
	suffix = strings.TrimPrefix(suffix, ".")
	if host == suffix {
		return true
	}
	if strings.HasSuffix(host, suffix) {
		prefixEnd := len(host) - len(suffix)
		if prefixEnd > 0 {
			return host[prefixEnd-1] == '.'
		}
	}
	return false
}

func parseHostAsIP(host string) (netip.Addr, error) {
	inner := host
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		inner = host[1 : len(host)-1]
	}
	return parseIPStrict(inner)
}

func contains(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
