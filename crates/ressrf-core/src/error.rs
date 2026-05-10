use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Sentinel error for all policy rejections. Callers use pattern matching
    /// (not string matching) to distinguish blocked requests from parse/DNS errors.
    Blocked(DenyReason),

    /// Input could not be parsed (malformed CIDR, URL, etc.).
    Parse(String),

    /// DNS resolution failed.
    DnsError(String),

    /// Configuration file could not be loaded or parsed.
    Config(String),

    /// Policy was already finalized; mutation rejected.
    PolicyFinalized,
}

impl Error {
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_))
    }

    #[must_use]
    pub fn deny_reason(&self) -> Option<&DenyReason> {
        match self {
            Self::Blocked(reason) => Some(reason),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked(reason) => write!(f, "blocked: {reason}"),
            Self::Parse(detail) => write!(f, "parse error: {detail}"),
            Self::DnsError(detail) => write!(f, "DNS error: {detail}"),
            Self::Config(detail) => write!(f, "config error: {detail}"),
            Self::PolicyFinalized => write!(f, "policy already finalized"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum MatchReason {
    Allowed(AllowReason),
    Denied(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AllowReason {
    InAllowList { cidr: String },
    AllowOverride { cidr: String },
    PresetExternal,
    NoConfiguredPolicy,
    TrustedDomainMatch { suffix: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DenyReason {
    // URL/URI structural
    UrlParseError { detail: String },
    SchemeNotAllowed { scheme: String },
    BareIpDeniedBeforeScheme { ip: String },
    HostnameInvalid { reason: String },
    IdnError { detail: String },
    UserinfoBypassAttempt,

    // Domain rules
    DomainNotInAllowList { host: String },
    DomainSuffixDenied { host: String, suffix: String },

    // DNS rules
    DnsResolveFailed { host: String, error: String },
    DnsEmptyResponse { host: String },
    AllResolvedIpsDenied { host: String, ips: Vec<String> },

    // CIDR rules
    InDenyCidr { cidr: String, source: DataTier },
    NotInAllowList { ip: String },

    // Multi-host
    MultiHostFallbackDenied { host: String, reason: Box<Self> },

    // Header rules
    RequiredHeaderMissing { name: String },
    DeniedHeaderPresent { name: String },

    // Redirect rules
    RedirectSchemeDowngrade { from: String, to: String },
    RedirectHostChanged { from_host: String, to_host: String },
    RedirectHopDenied { hop: u32, reason: Box<Self> },

    // Protocol rules
    ProtocolNotAllowed { protocol: String },
    PlaintextHttpDenied,

    // URL rules
    UrlRuleDenied { url: String },
    UrlRuleNotInAllowList { url: String },

    // Catch-all
    ExplicitDenyList { cidr: String },
    PolicyImmutabilityViolation,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UrlParseError { detail } => write!(f, "URL parse error: {detail}"),
            Self::SchemeNotAllowed { scheme } => write!(f, "scheme not allowed: {scheme}"),
            Self::BareIpDeniedBeforeScheme { ip } => {
                write!(f, "bare IP denied before scheme check: {ip}")
            }
            Self::HostnameInvalid { reason } => write!(f, "hostname invalid: {reason}"),
            Self::IdnError { detail } => write!(f, "IDN error: {detail}"),
            Self::UserinfoBypassAttempt => write!(f, "userinfo bypass attempt detected"),
            Self::DomainNotInAllowList { host } => {
                write!(f, "domain not in allow list: {host}")
            }
            Self::DomainSuffixDenied { host, suffix } => {
                write!(f, "domain suffix denied: {host} matches {suffix}")
            }
            Self::DnsResolveFailed { host, error } => {
                write!(f, "DNS resolve failed for {host}: {error}")
            }
            Self::DnsEmptyResponse { host } => write!(f, "DNS returned empty for {host}"),
            Self::AllResolvedIpsDenied { host, .. } => {
                write!(f, "all resolved IPs denied for {host}")
            }
            Self::InDenyCidr { cidr, source } => {
                write!(f, "IP in deny CIDR {cidr} (source: {source:?})")
            }
            Self::NotInAllowList { ip } => write!(f, "IP not in allow list: {ip}"),
            Self::MultiHostFallbackDenied { host, reason } => {
                write!(f, "multi-host fallback denied for {host}: {reason}")
            }
            Self::RequiredHeaderMissing { name } => {
                write!(f, "required header missing: {name}")
            }
            Self::DeniedHeaderPresent { name } => {
                write!(f, "denied header present: {name}")
            }
            Self::RedirectSchemeDowngrade { from, to } => {
                write!(f, "redirect scheme downgrade: {from} -> {to}")
            }
            Self::RedirectHostChanged { from_host, to_host } => {
                write!(f, "redirect host changed: {from_host} -> {to_host}")
            }
            Self::RedirectHopDenied { hop, reason } => {
                write!(f, "redirect hop {hop} denied: {reason}")
            }
            Self::ProtocolNotAllowed { protocol } => {
                write!(f, "protocol not allowed: {protocol}")
            }
            Self::PlaintextHttpDenied => write!(f, "plaintext HTTP denied"),
            Self::UrlRuleDenied { url } => write!(f, "URL denied by rule: {url}"),
            Self::UrlRuleNotInAllowList { url } => {
                write!(f, "URL not in allow list: {url}")
            }
            Self::ExplicitDenyList { cidr } => write!(f, "in explicit deny list: {cidr}"),
            Self::PolicyImmutabilityViolation => {
                write!(f, "policy mutation after finalization")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataTier {
    Iana,
    Override,
    CspMetadata,
    CloudAws,
    CloudAzure,
    CloudGcp,
    DomainSuffix,
    UserDeny,
    UserAllow,
}
