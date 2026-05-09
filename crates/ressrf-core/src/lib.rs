#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod audit;
pub mod cidr;
pub mod cloud;
pub mod error;
pub mod ip_ranges;
pub mod policy;
#[cfg(feature = "std")]
pub mod service_ranges;
pub mod uri_validator;

pub use audit::{AuditEvent, AuditSink};
pub use cidr::Cidr;
pub use cloud::CloudProvider;
pub use error::{Error, Result};
pub use policy::{Policy, PolicyBuilder, Preset};
#[cfg(feature = "std")]
pub use service_ranges::ServiceRangeTable;
pub use uri_validator::UriValidator;
