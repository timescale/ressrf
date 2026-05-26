package engine

import "fmt"

// DenyReason is the sealed-interface sum type for SSRF policy rejections.
// Each implementation carries only the fields relevant to its variant, so a
// SchemeNotAllowed reason cannot accidentally carry a CIDR or a Host that
// nothing reads.
//
// Callers in Go 1.21+ should switch on the concrete type:
//
//	switch r := reason.(type) {
//	case *SchemeNotAllowed: ...
//	case *InDenyCIDR:       ...
//	}
//
// or query the kind tag via Kind() when only categorical action is needed.
type DenyReason interface {
	error
	Kind() DenyKind
	isDenyReason() // sealed
}

// --- URL / scheme variants ---------------------------------------------------

// UrlParseError signals the URL string could not be parsed into components.
type UrlParseError struct{ Detail string }

func (e *UrlParseError) Error() string { return "URL parse error: " + e.Detail }
func (*UrlParseError) Kind() DenyKind  { return DenyUrlParseError }
func (*UrlParseError) isDenyReason()   {}

// SchemeNotAllowed signals the URL's scheme is outside the allow-list.
type SchemeNotAllowed struct{ Scheme string }

func (e *SchemeNotAllowed) Error() string { return "scheme not allowed: " + e.Scheme }
func (*SchemeNotAllowed) Kind() DenyKind  { return DenySchemeNotAllowed }
func (*SchemeNotAllowed) isDenyReason()   {}

// SchemeRequired signals a URL with no scheme was rejected.
type SchemeRequired struct{}

func (*SchemeRequired) Error() string  { return "URL scheme is required (e.g. http:// or https://)" }
func (*SchemeRequired) Kind() DenyKind { return DenySchemeRequired }
func (*SchemeRequired) isDenyReason()  {}

// BareIPDeniedBeforeScheme signals the URL contained an IP literal that was
// rejected by the network-level policy before any further checks.
type BareIPDeniedBeforeScheme struct{ Host string }

func (e *BareIPDeniedBeforeScheme) Error() string {
	return "bare IP denied before scheme check: " + e.Host
}
func (*BareIPDeniedBeforeScheme) Kind() DenyKind { return DenyBareIpDeniedBeforeScheme }
func (*BareIPDeniedBeforeScheme) isDenyReason()  {}

// HostnameInvalid signals the host failed a structural check (control bytes,
// double-dash without xn--, etc.).
type HostnameInvalid struct{ Detail string }

func (e *HostnameInvalid) Error() string { return "hostname invalid: " + e.Detail }
func (*HostnameInvalid) Kind() DenyKind  { return DenyHostnameInvalid }
func (*HostnameInvalid) isDenyReason()   {}

// AmbiguousIPEncoding signals the host looked like an IP in a non-canonical
// form (octal, hex, decimal-integer, shorthand) and was rejected before DNS.
type AmbiguousIPEncoding struct {
	Host string
	Form string
}

func (e *AmbiguousIPEncoding) Error() string {
	return fmt.Sprintf("ambiguous IP encoding (%s) not allowed: %s", e.Form, e.Host)
}
func (*AmbiguousIPEncoding) Kind() DenyKind { return DenyAmbiguousIpEncoding }
func (*AmbiguousIPEncoding) isDenyReason()  {}

// UserinfoBypassAttempt signals %40 or @ confusion in the URL authority.
type UserinfoBypassAttempt struct{}

func (*UserinfoBypassAttempt) Error() string  { return "userinfo bypass attempt detected" }
func (*UserinfoBypassAttempt) Kind() DenyKind { return DenyUserinfoBypassAttempt }
func (*UserinfoBypassAttempt) isDenyReason()  {}

// --- domain rule variants ----------------------------------------------------

// DomainNotInAllowList signals the host failed the trusted-suffix allow-list.
type DomainNotInAllowList struct{ Host string }

func (e *DomainNotInAllowList) Error() string { return "domain not in allow list: " + e.Host }
func (*DomainNotInAllowList) Kind() DenyKind  { return DenyDomainNotInAllowList }
func (*DomainNotInAllowList) isDenyReason()   {}

// DomainSuffixDenied signals the host matched a denied domain suffix.
type DomainSuffixDenied struct {
	Host   string
	Suffix string
}

func (e *DomainSuffixDenied) Error() string {
	return fmt.Sprintf("domain suffix denied: %s matches %s", e.Host, e.Suffix)
}
func (*DomainSuffixDenied) Kind() DenyKind { return DenyDomainSuffixDenied }
func (*DomainSuffixDenied) isDenyReason()  {}

// --- DNS / network variants --------------------------------------------------

// DnsEmptyResponse signals the resolver returned no IPs for the host, or the
// IP list passed to IsNetworkAllowed was empty.
type DnsEmptyResponse struct{ Host string }

func (e *DnsEmptyResponse) Error() string {
	if e.Host == "" {
		return "DNS returned empty"
	}
	return "DNS returned empty for " + e.Host
}
func (*DnsEmptyResponse) Kind() DenyKind { return DenyDnsEmptyResponse }
func (*DnsEmptyResponse) isDenyReason()  {}

// InDenyCIDR signals an IP fell inside a CIDR range on the deny list.
type InDenyCIDR struct {
	CIDR   string
	Source DataTier
}

func (e *InDenyCIDR) Error() string {
	return fmt.Sprintf("IP in deny CIDR %s (source: %s)", e.CIDR, e.Source)
}
func (*InDenyCIDR) Kind() DenyKind { return DenyInDenyCidr }
func (*InDenyCIDR) isDenyReason()  {}

// NotInAllowList signals an IP failed the InternalOnly preset's allow-list.
type NotInAllowList struct{ Host string }

func (e *NotInAllowList) Error() string { return "IP not in allow list: " + e.Host }
func (*NotInAllowList) Kind() DenyKind  { return DenyNotInAllowList }
func (*NotInAllowList) isDenyReason()   {}

// MultiHostFallbackDenied wraps the rejection of one host in a connection
// string fallback list (e.g. Postgres multi-host). Inner is the host-specific
// reason; Host is the rejected entry.
type MultiHostFallbackDenied struct {
	Host  string
	Inner DenyReason
}

func (e *MultiHostFallbackDenied) Error() string {
	inner := ""
	if e.Inner != nil {
		inner = e.Inner.Error()
	}
	return fmt.Sprintf("multi-host fallback denied for %s: %s", e.Host, inner)
}
func (*MultiHostFallbackDenied) Kind() DenyKind { return DenyMultiHostFallbackDenied }
func (*MultiHostFallbackDenied) isDenyReason()  {}

// --- redirect / protocol variants --------------------------------------------

// RedirectSchemeDowngrade signals a redirect chain stepped from a higher to a
// lower trust scheme (typically https → http).
type RedirectSchemeDowngrade struct {
	From string
	To   string
}

func (e *RedirectSchemeDowngrade) Error() string {
	return fmt.Sprintf("redirect scheme downgrade: %s -> %s", e.From, e.To)
}
func (*RedirectSchemeDowngrade) Kind() DenyKind { return DenyRedirectSchemeDowngrade }
func (*RedirectSchemeDowngrade) isDenyReason()  {}

// PlaintextHttpDenied signals the policy required HTTPS but plain HTTP was
// supplied.
type PlaintextHttpDenied struct{}

func (*PlaintextHttpDenied) Error() string  { return "plaintext HTTP denied" }
func (*PlaintextHttpDenied) Kind() DenyKind { return DenyPlaintextHttpDenied }
func (*PlaintextHttpDenied) isDenyReason()  {}

// --- URL rule variants -------------------------------------------------------

// UrlRuleDenied signals a URL matched an explicit deny rule.
type UrlRuleDenied struct{ URL string }

func (e *UrlRuleDenied) Error() string { return "URL denied by rule: " + e.URL }
func (*UrlRuleDenied) Kind() DenyKind  { return DenyUrlRuleDenied }
func (*UrlRuleDenied) isDenyReason()   {}

// UrlRuleNotInAllowList signals an allow-list ruleset exists but the URL
// matched no allow rule.
type UrlRuleNotInAllowList struct{ URL string }

func (e *UrlRuleNotInAllowList) Error() string { return "URL not in allow list: " + e.URL }
func (*UrlRuleNotInAllowList) Kind() DenyKind  { return DenyUrlRuleNotInAllowList }
func (*UrlRuleNotInAllowList) isDenyReason()   {}
