// Package engine is the native Go port of ressrf-core. It implements the SSRF
// policy engine without any WASM dependency. Public API lives in the parent
// ressrf package; this package is internal so callers cannot depend on it.
package engine

import "fmt"

// DataTier identifies where a CIDR entry came from. Mirrors Rust's DataTier
// enum and is surfaced in audit events and error messages.
type DataTier uint8

const (
	TierIana DataTier = iota
	TierOverride
	TierCspMetadata
	TierCloudAws
	TierCloudAzure
	TierCloudGcp
	TierDomainSuffix
	TierUserDeny
	TierUserAllow
)

func (t DataTier) String() string {
	switch t {
	case TierIana:
		return "Iana"
	case TierOverride:
		return "Override"
	case TierCspMetadata:
		return "CspMetadata"
	case TierCloudAws:
		return "CloudAws"
	case TierCloudAzure:
		return "CloudAzure"
	case TierCloudGcp:
		return "CloudGcp"
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
	DenyUrlParseError DenyKind = iota
	DenySchemeNotAllowed
	DenySchemeRequired
	DenyBareIpDeniedBeforeScheme
	DenyHostnameInvalid
	DenyAmbiguousIpEncoding
	DenyUserinfoBypassAttempt
	DenyDomainNotInAllowList
	DenyDomainSuffixDenied
	DenyDnsEmptyResponse
	DenyInDenyCidr
	DenyNotInAllowList
	DenyMultiHostFallbackDenied
	DenyRedirectSchemeDowngrade
	DenyPlaintextHttpDenied
	DenyUrlRuleDenied
	DenyUrlRuleNotInAllowList
)

func (k DenyKind) String() string {
	switch k {
	case DenyUrlParseError:
		return "url_parse_error"
	case DenySchemeNotAllowed:
		return "scheme_not_allowed"
	case DenySchemeRequired:
		return "scheme_required"
	case DenyBareIpDeniedBeforeScheme:
		return "bare_ip_denied_before_scheme"
	case DenyHostnameInvalid:
		return "hostname_invalid"
	case DenyAmbiguousIpEncoding:
		return "ambiguous_ip_encoding"
	case DenyUserinfoBypassAttempt:
		return "userinfo_bypass_attempt"
	case DenyDomainNotInAllowList:
		return "domain_not_in_allow_list"
	case DenyDomainSuffixDenied:
		return "domain_suffix_denied"
	case DenyDnsEmptyResponse:
		return "dns_empty_response"
	case DenyInDenyCidr:
		return "in_deny_cidr"
	case DenyNotInAllowList:
		return "not_in_allow_list"
	case DenyMultiHostFallbackDenied:
		return "multi_host_fallback_denied"
	case DenyRedirectSchemeDowngrade:
		return "redirect_scheme_downgrade"
	case DenyPlaintextHttpDenied:
		return "plaintext_http_denied"
	case DenyUrlRuleDenied:
		return "url_rule_denied"
	case DenyUrlRuleNotInAllowList:
		return "url_rule_not_in_allow_list"
	}
	return fmt.Sprintf("DenyKind(%d)", uint8(k))
}

// ParseError is returned for malformed input (CIDRs, URLs) that is not the
// result of policy evaluation. The public ressrf package wraps it inside its
// own BlockedError when surfacing to callers.
type ParseError struct{ Detail string }

func (p *ParseError) Error() string { return "parse error: " + p.Detail }
