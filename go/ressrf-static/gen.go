// Package ressrfstatic — config sync directives.
//
// The canonical policy data lives in crates/ressrf-core/config/ and is
// refreshed monthly by scripts/generate_ip_ranges.py. Cloud-provider JSON
// blobs each live in their own sub-package so the Go linker can prune
// unused providers from the binary (Azure alone is ~3.1 MB).
//
// CI runs `go generate` then `git diff --exit-code` on the embedded paths
// to catch drift when the canonical files are updated but the Go-side
// copies are not.
package ressrfstatic

//go:generate sh -c "cp ../../crates/ressrf-core/config/ip_ranges.json ./config/"
//go:generate sh -c "cp ../../crates/ressrf-core/config/domains_aws.json ./cloud/aws/"
//go:generate sh -c "cp ../../crates/ressrf-core/config/domains_azure.json ./cloud/azure/"
//go:generate sh -c "cp ../../crates/ressrf-core/config/domains_gcp.json ./cloud/gcp/"
