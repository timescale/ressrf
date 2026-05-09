use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::MatchReason;

/// Events emitted by the policy engine at each decision point.
/// The library never logs credentials, connection strings, or request bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum AuditEvent {
    HostValidated {
        host: String,
        resolved_ips: Vec<String>,
        allowed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_input: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_reason: Option<MatchReason>,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_context: Option<BTreeMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_version: Option<String>,
    },
    UrlValidated {
        url: String,
        host: String,
        scheme: String,
        allowed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_input: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_reason: Option<MatchReason>,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_context: Option<BTreeMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_version: Option<String>,
    },
    ConnectionAttempt {
        protocol: String,
        remote_addr: String,
        allowed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_input: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_reason: Option<MatchReason>,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_context: Option<BTreeMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_version: Option<String>,
    },
    RedirectIntercepted {
        from_url: String,
        to_url: String,
        allowed: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_input: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        match_reason: Option<MatchReason>,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_context: Option<BTreeMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_version: Option<String>,
    },
    PolicyCreated {
        preset: String,
        cloud_modules: Vec<String>,
        deny_count: usize,
        allow_count: usize,
    },
}

/// Trait for audit sinks. Language bindings implement this.
/// The Policy holds an `Option<Box<dyn AuditSink>>`, giving zero overhead when None.
pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &AuditEvent);
}

/// No-op sink for testing.
#[derive(Debug, Default)]
pub struct NullSink;

impl AuditSink for NullSink {
    fn emit(&self, _event: &AuditEvent) {}
}

/// Collects events for testing.
#[cfg(any(test, feature = "std"))]
#[derive(Debug, Default)]
pub struct CollectingSink {
    events: std::sync::Mutex<Vec<AuditEvent>>,
}

#[cfg(any(test, feature = "std"))]
impl CollectingSink {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

#[cfg(any(test, feature = "std"))]
impl AuditSink for CollectingSink {
    fn emit(&self, event: &AuditEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}
