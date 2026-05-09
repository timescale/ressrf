//! AWS cloud module: IMDS/ECS deny ranges and internal domain suffixes.
//!
//! Constants are generated at build time from `config/domains_aws.json` via `build.rs`.

include!(concat!(env!("OUT_DIR"), "/cloud_aws_generated.rs"));
