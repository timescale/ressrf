use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::audit::{AuditEvent, AuditSink};
use crate::cidr::{Cidr, CidrSet};
use crate::error::{DataTier, DenyReason, Error};
use crate::ip_ranges;

/// Policy presets that determine default allow/deny behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    /// Default-deny: every IP must be in the allow list.
    InternalOnly,
    /// Deny known internal/metadata ranges; allow everything else.
    ExternalOnly,
    /// No restrictions (audit-only mode).
    None,
}

/// Header validation rules.
#[derive(Debug, Clone, Default)]
pub struct HeaderRules {
    pub required: Vec<String>,
    pub denied: Vec<String>,
    pub auto_xff: bool,
}

/// Protocol-level rules.
#[derive(Debug, Clone)]
pub struct ProtocolRules {
    pub allow_plaintext_http: bool,
    pub require_https: bool,
}

impl Default for ProtocolRules {
    fn default() -> Self {
        Self {
            allow_plaintext_http: false,
            require_https: true,
        }
    }
}

/// Builder for constructing an immutable Policy.
pub struct PolicyBuilder {
    preset: Preset,
    deny_set: CidrSet,
    allow_set: CidrSet,
    header_rules: HeaderRules,
    protocol_rules: ProtocolRules,
    cloud_modules: Vec<String>,
    audit_sink: Option<Box<dyn AuditSink>>,
}

impl core::fmt::Debug for PolicyBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyBuilder")
            .field("preset", &self.preset)
            .field("deny_count", &self.deny_set.len())
            .field("allow_count", &self.allow_set.len())
            .field("cloud_modules", &self.cloud_modules)
            .finish_non_exhaustive()
    }
}

impl PolicyBuilder {
    #[must_use]
    pub fn new(preset: Preset) -> Self {
        Self {
            preset,
            deny_set: CidrSet::new(),
            allow_set: CidrSet::new(),
            header_rules: HeaderRules::default(),
            protocol_rules: ProtocolRules::default(),
            cloud_modules: Vec::new(),
            audit_sink: None,
        }
    }

    /// Start with the `ExternalOnly` preset (deny known internal, allow rest).
    #[must_use]
    pub fn external_only() -> Self {
        Self::new(Preset::ExternalOnly)
    }

    /// Start with the `InternalOnly` preset (default-deny, allow-list required).
    #[must_use]
    pub fn internal_only() -> Self {
        Self::new(Preset::InternalOnly)
    }

    /// Add CIDRs to the deny list.
    pub fn add_denied(&mut self, cidr_strs: &[&str]) -> &mut Self {
        for &s in cidr_strs {
            if let Ok(cidr) = Cidr::parse_loose(s, DataTier::UserDeny) {
                self.deny_set.add(cidr);
            }
        }
        self
    }

    /// Add CIDRs to the allow list (allow overrides deny).
    pub fn add_allowed(&mut self, cidr_strs: &[&str]) -> &mut Self {
        for &s in cidr_strs {
            if let Ok(cidr) = Cidr::parse_loose(s, DataTier::UserAllow) {
                self.allow_set.add(cidr);
            }
        }
        self
    }

    /// Configure header rules.
    pub fn header_rules(&mut self, rules: HeaderRules) -> &mut Self {
        self.header_rules = rules;
        self
    }

    /// Configure protocol rules.
    pub fn protocol_rules(&mut self, rules: ProtocolRules) -> &mut Self {
        self.protocol_rules = rules;
        self
    }

    /// Register a cloud module by name and add its deny ranges.
    pub fn with_cloud_deny(&mut self, name: &str, ranges: &[&str]) -> &mut Self {
        self.cloud_modules.push(String::from(name));
        let source = match name {
            "aws" => DataTier::CloudAws,
            "azure" => DataTier::CloudAzure,
            "gcp" => DataTier::CloudGcp,
            _ => DataTier::UserDeny,
        };
        for &s in ranges {
            if let Ok(cidr) = Cidr::parse_loose(s, source) {
                self.deny_set.add(cidr);
            }
        }
        self
    }

    /// Load a cloud provider module: adds its deny ranges to the policy.
    ///
    /// This method adds the provider's metadata endpoint IPs to the deny set.
    /// For domain-level validation (denied/allowed suffixes), use
    /// `UriValidator::with_cloud_provider` alongside this.
    pub fn with_cloud(&mut self, provider: crate::cloud::CloudProvider) -> &mut Self {
        self.with_cloud_deny(provider.name(), provider.deny_ranges())
    }

    /// Set the audit sink.
    pub fn audit_sink(&mut self, sink: Box<dyn AuditSink>) -> &mut Self {
        self.audit_sink = Some(sink);
        self
    }

    /// Build the immutable policy. After this, no further modifications are possible.
    pub fn build(mut self) -> Policy {
        // Load default deny set for ExternalOnly preset.
        // InternalOnly does not need it since it only checks the allow list,
        // but we still load it so that future features (e.g. audit-only deny reporting)
        // have the data available without a breaking change.
        if self.preset == Preset::ExternalOnly {
            let defaults = ip_ranges::default_deny_set();
            for cidr in defaults {
                self.deny_set.add(cidr);
            }
        }

        let deny_count = self.deny_set.len();
        let allow_count = self.allow_set.len();

        let policy = Policy {
            preset: self.preset,
            deny_set: self.deny_set,
            allow_set: self.allow_set,
            header_rules: self.header_rules,
            protocol_rules: self.protocol_rules,
            cloud_modules: self.cloud_modules.clone(),
            audit_sink: self.audit_sink,
        };

        // Emit PolicyCreated audit event
        policy.emit_audit(&AuditEvent::PolicyCreated {
            preset: alloc::format!("{:?}", self.preset),
            cloud_modules: self.cloud_modules,
            deny_count,
            allow_count,
        });

        policy
    }
}

/// An immutable, finalized policy. All validation calls go through this.
pub struct Policy {
    preset: Preset,
    deny_set: CidrSet,
    allow_set: CidrSet,
    header_rules: HeaderRules,
    protocol_rules: ProtocolRules,
    cloud_modules: Vec<String>,
    audit_sink: Option<Box<dyn AuditSink>>,
}

impl core::fmt::Debug for Policy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Policy")
            .field("preset", &self.preset)
            .field("deny_count", &self.deny_set.len())
            .field("allow_count", &self.allow_set.len())
            .field("cloud_modules", &self.cloud_modules)
            .finish_non_exhaustive()
    }
}

impl Policy {
    /// Check if a set of resolved IPs is allowed by this policy.
    ///
    /// For `InternalOnly`: every IP must be in the allow list.
    /// For `ExternalOnly`: every IP must not be in the deny list (unless also in allow list).
    /// For `None`: always allowed.
    pub fn is_network_allowed(&self, ips: &[IpAddr]) -> crate::Result<()> {
        if ips.is_empty() {
            return Err(Error::Blocked(DenyReason::DnsEmptyResponse {
                host: String::new(),
            }));
        }

        match self.preset {
            Preset::None => return Ok(()),
            Preset::InternalOnly => {
                for &ip in ips {
                    if self.allow_set.contains(ip).is_none() {
                        return Err(Error::Blocked(DenyReason::NotInAllowList {
                            ip: alloc::format!("{ip}"),
                        }));
                    }
                }
            }
            Preset::ExternalOnly => {
                for &ip in ips {
                    // Allow overrides deny
                    if self.allow_set.contains(ip).is_some() {
                        continue;
                    }
                    if let Some(denied_cidr) = self.deny_set.contains(ip) {
                        return Err(Error::Blocked(DenyReason::InDenyCidr {
                            cidr: alloc::format!("{denied_cidr}"),
                            source: denied_cidr.source(),
                        }));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate a list of hosts (for multi-host connection strings like Postgres fallbacks).
    /// Every host in the list must pass individually.
    pub fn validate_all_hosts(&self, hosts: &[&str]) -> crate::Result<()> {
        for &host in hosts {
            if let Ok(ip) = host.parse::<IpAddr>() {
                self.is_network_allowed(&[ip]).map_err(|e| {
                    if let Error::Blocked(reason) = e {
                        Error::Blocked(DenyReason::MultiHostFallbackDenied {
                            host: String::from(host),
                            reason: Box::new(reason),
                        })
                    } else {
                        e
                    }
                })?;
            }
            // Non-IP hosts require DNS resolution (handled by protocol modules)
        }
        Ok(())
    }

    /// Check required/denied headers.
    pub fn validate_headers(&self, headers: &[(&str, &str)]) -> crate::Result<()> {
        let header_names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();

        for required in &self.header_rules.required {
            let req_lower = required.to_lowercase();
            if !header_names.iter().any(|h| h.to_lowercase() == req_lower) {
                return Err(Error::Blocked(DenyReason::RequiredHeaderMissing {
                    name: required.clone(),
                }));
            }
        }

        for denied in &self.header_rules.denied {
            let denied_lower = denied.to_lowercase();
            if header_names
                .iter()
                .any(|h| h.to_lowercase() == denied_lower)
            {
                return Err(Error::Blocked(DenyReason::DeniedHeaderPresent {
                    name: denied.clone(),
                }));
            }
        }

        Ok(())
    }

    /// Check if a protocol scheme is allowed.
    pub fn validate_scheme(&self, scheme: &str) -> crate::Result<()> {
        let scheme_lower = scheme.to_lowercase();
        if scheme_lower == "http"
            && (self.protocol_rules.require_https || !self.protocol_rules.allow_plaintext_http)
        {
            return Err(Error::Blocked(DenyReason::PlaintextHttpDenied));
        }
        Ok(())
    }

    #[must_use]
    pub fn preset(&self) -> Preset {
        self.preset
    }

    #[must_use]
    pub fn header_rules(&self) -> &HeaderRules {
        &self.header_rules
    }

    #[must_use]
    pub fn protocol_rules(&self) -> &ProtocolRules {
        &self.protocol_rules
    }

    /// Emit an audit event if a sink is configured.
    pub(crate) fn emit_audit(&self, event: &AuditEvent) {
        if let Some(ref sink) = self.audit_sink {
            sink.emit(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_only_blocks_private() {
        let policy = PolicyBuilder::external_only().build();
        let private_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let result = policy.is_network_allowed(&[private_ip]);
        assert!(result.is_err());
        assert!(result.unwrap_err().is_blocked());
    }

    #[test]
    fn external_only_allows_public() {
        let policy = PolicyBuilder::external_only().build();
        let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(policy.is_network_allowed(&[public_ip]).is_ok());
    }

    #[test]
    fn external_only_blocks_imds() {
        let policy = PolicyBuilder::external_only().build();
        let imds: IpAddr = "169.254.169.254".parse().unwrap();
        let result = policy.is_network_allowed(&[imds]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_blocked());
    }

    #[test]
    fn allow_overrides_deny() {
        let mut builder = PolicyBuilder::external_only();
        builder.add_allowed(&["10.42.0.0/16"]);
        let policy = builder.build();

        // 10.42.x.x should be allowed even though 10.0.0.0/8 is in the deny set
        let ip: IpAddr = "10.42.1.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[ip]).is_ok());

        // Other 10.x.x.x still blocked
        let other: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[other]).is_err());
    }

    #[test]
    fn internal_only_requires_allow_list() {
        let mut builder = PolicyBuilder::internal_only();
        builder.add_allowed(&["203.0.113.0/24"]);
        let policy = builder.build();

        let allowed: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[allowed]).is_ok());

        let denied: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(policy.is_network_allowed(&[denied]).is_err());
    }

    #[test]
    fn none_preset_allows_everything() {
        let policy = PolicyBuilder::new(Preset::None).build();
        let private_ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[private_ip]).is_ok());
    }

    #[test]
    fn empty_ips_rejected() {
        let policy = PolicyBuilder::external_only().build();
        assert!(policy.is_network_allowed(&[]).is_err());
    }

    #[test]
    fn multi_host_all_must_pass() {
        let policy = PolicyBuilder::external_only().build();
        // Mixed: one public, one private
        let result = policy.validate_all_hosts(&["8.8.8.8", "10.0.0.1"]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            Error::Blocked(DenyReason::MultiHostFallbackDenied { .. })
        ));
    }

    #[test]
    fn header_rules_required() {
        let mut builder = PolicyBuilder::external_only();
        builder.header_rules(HeaderRules {
            required: alloc::vec![String::from("Authorization")],
            denied: Vec::new(),
            auto_xff: false,
        });
        let policy = builder.build();

        let result = policy.validate_headers(&[("Content-Type", "application/json")]);
        assert!(matches!(
            result,
            Err(Error::Blocked(DenyReason::RequiredHeaderMissing { .. }))
        ));

        let result = policy.validate_headers(&[("Authorization", "Bearer xyz")]);
        assert!(result.is_ok());
    }

    #[test]
    fn header_rules_denied() {
        let mut builder = PolicyBuilder::external_only();
        builder.header_rules(HeaderRules {
            required: Vec::new(),
            denied: alloc::vec![String::from("X-Real-IP")],
            auto_xff: false,
        });
        let policy = builder.build();

        let result = policy.validate_headers(&[("X-Real-IP", "10.0.0.1")]);
        assert!(matches!(
            result,
            Err(Error::Blocked(DenyReason::DeniedHeaderPresent { .. }))
        ));
    }

    #[test]
    fn plaintext_http_denied_by_default() {
        let policy = PolicyBuilder::external_only().build();
        assert!(policy.validate_scheme("http").is_err());
        assert!(policy.validate_scheme("https").is_ok());
    }

    #[test]
    fn audit_event_emitted_on_build() {
        use crate::audit::CollectingSink;
        use alloc::sync::Arc;

        let sink = Arc::new(CollectingSink::new());
        let mut builder = PolicyBuilder::external_only();
        builder.audit_sink(Box::new(ArcSink(Arc::clone(&sink))));
        let _policy = builder.build();

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], AuditEvent::PolicyCreated { .. }));
    }

    /// Wrapper to use Arc<CollectingSink> as a Box<dyn AuditSink>.
    struct ArcSink(alloc::sync::Arc<crate::audit::CollectingSink>);

    impl AuditSink for ArcSink {
        fn emit(&self, event: &AuditEvent) {
            self.0.emit(event);
        }
    }

    #[test]
    fn allow_plaintext_http_when_configured() {
        let mut builder = PolicyBuilder::external_only();
        builder.protocol_rules(ProtocolRules {
            allow_plaintext_http: true,
            require_https: false,
        });
        let policy = builder.build();
        assert!(policy.validate_scheme("http").is_ok());
        assert!(policy.validate_scheme("https").is_ok());
    }

    #[test]
    fn require_https_overrides_allow_plaintext() {
        let mut builder = PolicyBuilder::external_only();
        builder.protocol_rules(ProtocolRules {
            allow_plaintext_http: true,
            require_https: true,
        });
        let policy = builder.build();
        assert!(policy.validate_scheme("http").is_err());
    }

    #[test]
    fn with_cloud_deny_adds_custom_ranges() {
        let mut builder = PolicyBuilder::external_only();
        builder.with_cloud_deny("custom_cloud", &["198.51.100.0/24"]);
        let policy = builder.build();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[ip]).is_err());
    }

    #[test]
    fn multiple_cloud_modules_combine() {
        let mut builder = PolicyBuilder::external_only();
        builder.with_cloud(crate::CloudProvider::Aws);
        builder.with_cloud(crate::CloudProvider::Azure);
        let policy = builder.build();

        let aws_imds: IpAddr = "169.254.170.2".parse().unwrap();
        let azure_wire: IpAddr = "168.63.129.16".parse().unwrap();
        assert!(policy.is_network_allowed(&[aws_imds]).is_err());
        assert!(policy.is_network_allowed(&[azure_wire]).is_err());
    }

    #[test]
    fn user_deny_cidrs_block_specific_ranges() {
        let mut builder = PolicyBuilder::external_only();
        builder.add_denied(&["203.0.113.0/24"]);
        let policy = builder.build();

        let blocked: IpAddr = "203.0.113.50".parse().unwrap();
        let allowed: IpAddr = "203.0.114.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[blocked]).is_err());
        assert!(policy.is_network_allowed(&[allowed]).is_ok());
    }

    #[test]
    fn header_rules_case_insensitive() {
        let mut builder = PolicyBuilder::external_only();
        builder.header_rules(HeaderRules {
            required: alloc::vec![String::from("x-request-id")],
            denied: alloc::vec![String::from("X-FORWARDED-FOR")],
            auto_xff: false,
        });
        let policy = builder.build();

        assert!(policy
            .validate_headers(&[("X-Request-ID", "abc123")])
            .is_ok());
        assert!(policy
            .validate_headers(&[("x-forwarded-for", "1.2.3.4")])
            .is_err());
    }

    #[test]
    fn validate_scheme_case_insensitive() {
        let policy = PolicyBuilder::external_only().build();
        assert!(policy.validate_scheme("HTTP").is_err());
        assert!(policy.validate_scheme("HTTPS").is_ok());
        assert!(policy.validate_scheme("Https").is_ok());
    }

    #[test]
    fn all_ips_must_pass_external_only() {
        let policy = PolicyBuilder::external_only().build();
        let ips: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "93.184.216.34".parse().unwrap(),
        ];
        assert!(policy.is_network_allowed(&ips).is_ok());
    }

    #[test]
    fn one_blocked_ip_fails_entire_check() {
        let policy = PolicyBuilder::external_only().build();
        let ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap(), "192.168.0.1".parse().unwrap()];
        assert!(policy.is_network_allowed(&ips).is_err());
    }

    #[test]
    fn internal_only_empty_allow_blocks_all() {
        let policy = PolicyBuilder::internal_only().build();
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let private: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(policy.is_network_allowed(&[public]).is_err());
        assert!(policy.is_network_allowed(&[private]).is_err());
    }
}
