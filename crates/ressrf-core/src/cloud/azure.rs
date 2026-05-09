//! Azure cloud module: IMDS/Wireserver deny ranges and domain suffixes.
//!
//! Constants are generated at build time from `config/domains_azure.json` via `build.rs`.

include!(concat!(env!("OUT_DIR"), "/cloud_azure_generated.rs"));
