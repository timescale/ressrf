// Package engine is the native Go port of ressrf-core. It implements the SSRF
// policy engine without any WASM dependency. Public API lives in the parent
// ressrf package; this package is internal so callers cannot depend on it.
package engine

import "fmt"

// DataTier identifies where a CIDR entry came from. Mirrors Rust's DataTier
// enum and is surfaced in audit events and error messages.
type DataTier uint8

const (
	TierIANA DataTier = iota
	TierOverride
	TierCSPMetadata
	TierCloudAWS
	TierCloudAzure
	TierCloudGCP
	TierDomainSuffix
	TierUserDeny
	TierUserAllow
)

func (t DataTier) String() string {
	switch t {
	case TierIANA:
		return "IANA"
	case TierOverride:
		return "Override"
	case TierCSPMetadata:
		return "CSPMetadata"
	case TierCloudAWS:
		return "CloudAWS"
	case TierCloudAzure:
		return "CloudAzure"
	case TierCloudGCP:
		return "CloudGCP"
	case TierDomainSuffix:
		return "DomainSuffix"
	case TierUserDeny:
		return "UserDeny"
	case TierUserAllow:
		return "UserAllow"
	}
	return fmt.Sprintf("DataTier(%d)", uint8(t))
}

// DenyKind enumerates the structured deny reasons. Mirrors Rust's DenyReason.
type DenyKind uint8

const (
	DenyURLParseError DenyKind = iota
	DenySchemeNotAllowed
	DenySchemeRequired
	DenyBareIPDeniedBeforeScheme
	DenyHostnameInvalid
	DenyAmbiguousIPEncoding
	DenyUserinfoBypassAttempt
	DenyDomainNotInAllowList
	DenyDomainSuffixDenied
	DenyDNSEmptyResponse
	DenyInDenyCIDR
	DenyNotInAllowList
	DenyMultiHostFallbackDenied
	DenyRedirectSchemeDowngrade
	DenyPlaintextHTTPDenied
	DenyURLRuleDenied
	DenyURLRuleNotInAllowList
)

func (k DenyKind) String() string {
	switch k {
	case DenyURLParseError:
		return "url_parse_error"
	case DenySchemeNotAllowed:
		return "scheme_not_allowed"
	case DenySchemeRequired:
		return "scheme_required"
	case DenyBareIPDeniedBeforeScheme:
		return "bare_ip_denied_before_scheme"
	case DenyHostnameInvalid:
		return "hostname_invalid"
	case DenyAmbiguousIPEncoding:
		return "ambiguous_ip_encoding"
	case DenyUserinfoBypassAttempt:
		return "userinfo_bypass_attempt"
	case DenyDomainNotInAllowList:
		return "domain_not_in_allow_list"
	case DenyDomainSuffixDenied:
		return "domain_suffix_denied"
	case DenyDNSEmptyResponse:
		return "dns_empty_response"
	case DenyInDenyCIDR:
		return "in_deny_cidr"
	case DenyNotInAllowList:
		return "not_in_allow_list"
	case DenyMultiHostFallbackDenied:
		return "multi_host_fallback_denied"
	case DenyRedirectSchemeDowngrade:
		return "redirect_scheme_downgrade"
	case DenyPlaintextHTTPDenied:
		return "plaintext_http_denied"
	case DenyURLRuleDenied:
		return "url_rule_denied"
	case DenyURLRuleNotInAllowList:
		return "url_rule_not_in_allow_list"
	}
	return fmt.Sprintf("DenyKind(%d)", uint8(k))
}

// ParseError is returned for malformed input (CIDRs, URLs) that is not the
// result of policy evaluation. The public ressrf package wraps it inside its
// own BlockedError when surfacing to callers.
type ParseError struct{ Detail string }

func (p *ParseError) Error() string { return "parse error: " + p.Detail }
