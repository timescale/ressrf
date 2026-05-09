//! GCP cloud module: metadata server deny ranges and domain suffixes.
//!
//! Constants are generated at build time from `config/domains_gcp.json` via `build.rs`.

include!(concat!(env!("OUT_DIR"), "/cloud_gcp_generated.rs"));
