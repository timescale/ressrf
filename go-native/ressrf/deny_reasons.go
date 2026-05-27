package ressrf

import "github.com/timescale/ressrf/go-native/ressrf/internal/engine"

// DenyReason is the sealed-interface sum type returned by the engine when a
// request is blocked. Callers should type-switch on the concrete variants
// (see DenyReason implementations below) to inspect category-specific fields.
//
// Example:
//
//	switch r := err.(*BlockedError).Reason.(type) {
//	case *ressrf.InDenyCIDR:
//	    log.Warn("blocked by CIDR", "cidr", r.CIDR, "source", r.Source)
//	case *ressrf.SchemeNotAllowed:
//	    log.Warn("blocked scheme", "scheme", r.Scheme)
//	case *ressrf.BareIPDeniedBeforeScheme:
//	    log.Warn("blocked bare IP", "host", r.Host)
//	}
type DenyReason = engine.DenyReason

// DenyKind is the categorical tag carried by every DenyReason.
type DenyKind = engine.DenyKind

// DataTier identifies the provenance of a CIDR entry: IANA, cloud-provider
// modules, user-supplied lists, etc. Surfaced via InDenyCIDR.Source.
type DataTier = engine.DataTier

// Re-export the categorical DenyKind constants for switch convenience.
const (
	DenyURLParseError            = engine.DenyURLParseError
	DenySchemeNotAllowed         = engine.DenySchemeNotAllowed
	DenySchemeRequired           = engine.DenySchemeRequired
	DenyBareIPDeniedBeforeScheme = engine.DenyBareIPDeniedBeforeScheme
	DenyHostnameInvalid          = engine.DenyHostnameInvalid
	DenyAmbiguousIPEncoding      = engine.DenyAmbiguousIPEncoding
	DenyUserinfoBypassAttempt    = engine.DenyUserinfoBypassAttempt
	DenyDomainNotInAllowList     = engine.DenyDomainNotInAllowList
	DenyDomainSuffixDenied       = engine.DenyDomainSuffixDenied
	DenyDNSEmptyResponse         = engine.DenyDNSEmptyResponse
	DenyInDenyCIDR               = engine.DenyInDenyCIDR
	DenyNotInAllowList           = engine.DenyNotInAllowList
	DenyMultiHostFallbackDenied  = engine.DenyMultiHostFallbackDenied
	DenyRedirectSchemeDowngrade  = engine.DenyRedirectSchemeDowngrade
	DenyPlaintextHTTPDenied      = engine.DenyPlaintextHTTPDenied
	DenyURLRuleDenied            = engine.DenyURLRuleDenied
	DenyURLRuleNotInAllowList    = engine.DenyURLRuleNotInAllowList
)

// DataTier values, in case a caller wants to compare InDenyCIDR.Source.
const (
	TierIANA         = engine.TierIANA
	TierOverride     = engine.TierOverride
	TierCSPMetadata  = engine.TierCSPMetadata
	TierCloudAWS     = engine.TierCloudAWS
	TierCloudAzure   = engine.TierCloudAzure
	TierCloudGCP     = engine.TierCloudGCP
	TierDomainSuffix = engine.TierDomainSuffix
	TierUserDeny     = engine.TierUserDeny
	TierUserAllow    = engine.TierUserAllow
)

// The types below re-export every DenyReason variant from internal/engine.
// Callers type-switch on these in code that wants to act on
// category-specific data.
//
//revive:disable:exported
type (
	URLParseError            = engine.URLParseError
	SchemeNotAllowed         = engine.SchemeNotAllowed
	SchemeRequired           = engine.SchemeRequired
	BareIPDeniedBeforeScheme = engine.BareIPDeniedBeforeScheme
	HostnameInvalid          = engine.HostnameInvalid
	AmbiguousIPEncoding      = engine.AmbiguousIPEncoding
	UserinfoBypassAttempt    = engine.UserinfoBypassAttempt
	DomainNotInAllowList     = engine.DomainNotInAllowList
	DomainSuffixDenied       = engine.DomainSuffixDenied
	DNSEmptyResponse         = engine.DNSEmptyResponse
	InDenyCIDR               = engine.InDenyCIDR
	NotInAllowList           = engine.NotInAllowList
	MultiHostFallbackDenied  = engine.MultiHostFallbackDenied
	RedirectSchemeDowngrade  = engine.RedirectSchemeDowngrade
	PlaintextHTTPDenied      = engine.PlaintextHttpDenied
	URLRuleDenied            = engine.URLRuleDenied
	URLRuleNotInAllowList    = engine.URLRuleNotInAllowList
)

//revive:enable:exported
