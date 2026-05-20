package ressrfstatic

import (
	"errors"
	"fmt"
)

// ErrBlocked is the sentinel returned (wrapped) for every policy-denied
// destination. Use errors.Is(err, ErrBlocked) to distinguish policy
// rejections from transient network errors. Matches go/ressrf for callers
// that can swap imports.
var ErrBlocked = errors.New("ressrfstatic: request blocked by SSRF policy")

// DenyReason classifies why a URL or IP was blocked. Matches the
// crates/ressrf-core/src/error.rs::DenyReason enum so audit consumers across
// languages see consistent reason codes.
type DenyReason string

const (
	ReasonSchemeRequired           DenyReason = "scheme_required"
	ReasonSchemeNotAllowed         DenyReason = "scheme_not_allowed"
	ReasonURLParseError            DenyReason = "url_parse_error"
	ReasonHostnameInvalid          DenyReason = "hostname_invalid"
	ReasonAmbiguousIPEncoding      DenyReason = "ambiguous_ip_encoding"
	ReasonBareIPDeniedBeforeScheme DenyReason = "bare_ip_denied_before_scheme"
	ReasonUserinfoBypassAttempt    DenyReason = "userinfo_bypass_attempt"
	ReasonDomainSuffixDenied       DenyReason = "domain_suffix_denied"
	ReasonDomainNotInAllowList     DenyReason = "domain_not_in_allow_list"
	ReasonIPDeniedByCIDR           DenyReason = "ip_denied_by_cidr"
	ReasonIPNotInAllowList         DenyReason = "ip_not_in_allow_list"
	ReasonURLRuleDenied            DenyReason = "url_rule_denied"
	ReasonDNSEmptyResponse         DenyReason = "dns_empty_response"
)

// BlockedError is returned by Policy.IsAllowed and IsNetworkAllowed when a
// destination is denied. Mirrors go/ressrf/errors.go so callers see the same
// shape regardless of which backend is in use.
type BlockedError struct {
	Reason     DenyReason
	URL        string
	Host       string
	IP         string
	Suffix     string
	DetailText string
}

func (e *BlockedError) Error() string {
	switch {
	case e.URL != "" && e.DetailText != "":
		return fmt.Sprintf("ressrfstatic: blocked %s for %s: %s", e.Reason, e.URL, e.DetailText)
	case e.URL != "":
		return fmt.Sprintf("ressrfstatic: blocked %s for %s", e.Reason, e.URL)
	case e.IP != "":
		return fmt.Sprintf("ressrfstatic: blocked %s for IP %s", e.Reason, e.IP)
	case e.Host != "":
		return fmt.Sprintf("ressrfstatic: blocked %s for host %s", e.Reason, e.Host)
	default:
		return fmt.Sprintf("ressrfstatic: blocked %s", e.Reason)
	}
}

// Is reports whether target matches ErrBlocked. Lets callers use
// errors.Is(err, ErrBlocked) regardless of which Reason fired.
func (e *BlockedError) Is(target error) bool {
	return target == ErrBlocked
}

// Unwrap exposes the sentinel for errors.Is traversal.
func (e *BlockedError) Unwrap() error {
	return ErrBlocked
}
