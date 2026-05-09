//! `TracingSink` audit adapter for `ressrf-core`.
//!
//! Emits `tracing::event!` calls with structured fields for each audit event.
//! Wires into any existing `tracing_subscriber` pipeline without additional setup.
//!
//! # Usage
//!
//! ```ignore
//! use ressrf_core::{PolicyBuilder, Preset};
//! use ressrf_tracing::TracingSink;
//!
//! let policy = PolicyBuilder::new(Preset::ExternalOnly)
//!     .audit_sink(Box::new(TracingSink::default()))
//!     .build();
//! ```

use ressrf_core::audit::{AuditEvent, AuditSink};

/// Configurable log level for audit events.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AuditLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// A `tracing`-based audit sink that emits structured events.
///
/// Each `AuditEvent` is logged with fields prefixed by `ressrf.` so they
/// are easily filterable in observability pipelines.
#[derive(Debug, Clone)]
pub struct TracingSink {
    /// Level used for allowed/informational events.
    pub allow_level: AuditLevel,
    /// Level used for denied/blocked events.
    pub deny_level: AuditLevel,
}

impl Default for TracingSink {
    fn default() -> Self {
        Self {
            allow_level: AuditLevel::Info,
            deny_level: AuditLevel::Warn,
        }
    }
}

impl TracingSink {
    /// Create a sink with custom levels.
    pub fn new(allow_level: AuditLevel, deny_level: AuditLevel) -> Self {
        Self {
            allow_level,
            deny_level,
        }
    }
}

impl AuditSink for TracingSink {
    fn emit(&self, event: &AuditEvent) {
        match event {
            AuditEvent::PolicyCreated {
                preset,
                deny_count,
                allow_count,
                ..
            } => self.emit_policy_created(preset, *deny_count, *allow_count),
            AuditEvent::HostValidated {
                host,
                resolved_ips,
                allowed,
                match_reason,
                ..
            } => self.emit_host_validated(host, resolved_ips, *allowed, match_reason.as_ref()),
            AuditEvent::UrlValidated {
                url,
                host,
                scheme,
                allowed,
                match_reason,
                ..
            } => self.emit_url_validated(url, host, scheme, *allowed, match_reason.as_ref()),
            AuditEvent::ConnectionAttempt {
                protocol,
                remote_addr,
                allowed,
                match_reason,
                ..
            } => {
                self.emit_connection_attempt(
                    protocol,
                    remote_addr,
                    *allowed,
                    match_reason.as_ref(),
                );
            }
            AuditEvent::RedirectIntercepted {
                from_url,
                to_url,
                allowed,
                match_reason,
                ..
            } => self.emit_redirect(from_url, to_url, *allowed, match_reason.as_ref()),
        }
    }
}

impl TracingSink {
    fn emit_policy_created(&self, preset: &str, deny_count: usize, allow_count: usize) {
        emit_at_level(self.allow_level, || {
            tracing::info!(
                ressrf.event = "policy_created",
                ressrf.preset = %preset,
                ressrf.deny_count = deny_count,
                ressrf.allow_count = allow_count,
                "SSRF policy created"
            );
        });
    }

    fn emit_host_validated(
        &self,
        host: &str,
        resolved_ips: &[String],
        allowed: bool,
        match_reason: Option<&ressrf_core::error::MatchReason>,
    ) {
        let level = if allowed {
            self.allow_level
        } else {
            self.deny_level
        };
        emit_at_level(level, || {
            if allowed {
                tracing::info!(
                    ressrf.event = "host_validated",
                    ressrf.host = %host,
                    ressrf.ips = ?resolved_ips,
                    ressrf.allowed = true,
                    ressrf.reason = ?match_reason,
                    "host validated and allowed"
                );
            } else {
                tracing::warn!(
                    ressrf.event = "host_validated",
                    ressrf.host = %host,
                    ressrf.ips = ?resolved_ips,
                    ressrf.allowed = false,
                    ressrf.reason = ?match_reason,
                    "host BLOCKED by policy"
                );
            }
        });
    }

    fn emit_url_validated(
        &self,
        url: &str,
        host: &str,
        scheme: &str,
        allowed: bool,
        match_reason: Option<&ressrf_core::error::MatchReason>,
    ) {
        let level = if allowed {
            self.allow_level
        } else {
            self.deny_level
        };
        emit_at_level(level, || {
            if allowed {
                tracing::info!(
                    ressrf.event = "url_validated",
                    ressrf.url = %url,
                    ressrf.host = %host,
                    ressrf.scheme = %scheme,
                    ressrf.allowed = true,
                    ressrf.reason = ?match_reason,
                    "URL validated and allowed"
                );
            } else {
                tracing::warn!(
                    ressrf.event = "url_validated",
                    ressrf.url = %url,
                    ressrf.host = %host,
                    ressrf.scheme = %scheme,
                    ressrf.allowed = false,
                    ressrf.reason = ?match_reason,
                    "URL BLOCKED by policy"
                );
            }
        });
    }

    fn emit_connection_attempt(
        &self,
        protocol: &str,
        remote_addr: &str,
        allowed: bool,
        match_reason: Option<&ressrf_core::error::MatchReason>,
    ) {
        let level = if allowed {
            self.allow_level
        } else {
            self.deny_level
        };
        emit_at_level(level, || {
            if allowed {
                tracing::info!(
                    ressrf.event = "connection_attempt",
                    ressrf.protocol = %protocol,
                    ressrf.remote_addr = %remote_addr,
                    ressrf.allowed = true,
                    ressrf.reason = ?match_reason,
                    "connection allowed"
                );
            } else {
                tracing::warn!(
                    ressrf.event = "connection_attempt",
                    ressrf.protocol = %protocol,
                    ressrf.remote_addr = %remote_addr,
                    ressrf.allowed = false,
                    ressrf.reason = ?match_reason,
                    "connection BLOCKED by policy"
                );
            }
        });
    }

    fn emit_redirect(
        &self,
        from_url: &str,
        to_url: &str,
        allowed: bool,
        match_reason: Option<&ressrf_core::error::MatchReason>,
    ) {
        let level = if allowed {
            self.allow_level
        } else {
            self.deny_level
        };
        emit_at_level(level, || {
            if allowed {
                tracing::info!(
                    ressrf.event = "redirect_intercepted",
                    ressrf.from_url = %from_url,
                    ressrf.to_url = %to_url,
                    ressrf.allowed = true,
                    ressrf.reason = ?match_reason,
                    "redirect followed"
                );
            } else {
                tracing::warn!(
                    ressrf.event = "redirect_intercepted",
                    ressrf.from_url = %from_url,
                    ressrf.to_url = %to_url,
                    ressrf.allowed = false,
                    ressrf.reason = ?match_reason,
                    "redirect BLOCKED by policy"
                );
            }
        });
    }
}

/// Dispatch a closure only if the configured level is enabled.
fn emit_at_level<F: FnOnce()>(level: AuditLevel, f: F) {
    match level {
        AuditLevel::Trace => {
            if tracing::enabled!(tracing::Level::TRACE) {
                f();
            }
        }
        AuditLevel::Debug => {
            if tracing::enabled!(tracing::Level::DEBUG) {
                f();
            }
        }
        AuditLevel::Info => {
            if tracing::enabled!(tracing::Level::INFO) {
                f();
            }
        }
        AuditLevel::Warn => {
            if tracing::enabled!(tracing::Level::WARN) {
                f();
            }
        }
        AuditLevel::Error => {
            if tracing::enabled!(tracing::Level::ERROR) {
                f();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_implements_audit_sink_trait() {
        let sink = TracingSink::default();
        let event = AuditEvent::HostValidated {
            host: "example.com".into(),
            resolved_ips: vec!["93.184.216.34".into()],
            allowed: true,
            raw_input: None,
            match_reason: None,
            caller_context: None,
            policy_version: None,
        };
        sink.emit(&event);
    }

    #[test]
    fn sink_handles_blocked_event() {
        let sink = TracingSink::new(AuditLevel::Debug, AuditLevel::Error);
        let event = AuditEvent::HostValidated {
            host: "evil.internal".into(),
            resolved_ips: vec!["10.0.0.1".into()],
            allowed: false,
            raw_input: Some("evil.internal".into()),
            match_reason: None,
            caller_context: None,
            policy_version: None,
        };
        sink.emit(&event);
    }

    #[test]
    fn custom_levels() {
        let sink = TracingSink::new(AuditLevel::Trace, AuditLevel::Error);
        assert_eq!(sink.allow_level, AuditLevel::Trace);
        assert_eq!(sink.deny_level, AuditLevel::Error);
    }

    #[test]
    fn policy_created_event() {
        let sink = TracingSink::default();
        let event = AuditEvent::PolicyCreated {
            preset: "external_only".into(),
            cloud_modules: vec!["aws".into()],
            deny_count: 25,
            allow_count: 0,
        };
        sink.emit(&event);
    }
}
