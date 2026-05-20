// Package ressrfstatic — config sync directive.
//
// The canonical policy data lives in crates/ressrf-core/config/ and is
// refreshed monthly by scripts/generate_ip_ranges.py. The Go package consumes
// the same files via //go:embed, so we copy them into ./config/ here. CI runs
// `go generate` then `git diff --exit-code go/ressrf-static/config/` to catch
// drift when the canonical files are updated but the Go-side copies are not.
package ressrfstatic

//go:generate sh -c "cp ../../crates/ressrf-core/config/ip_ranges.json ../../crates/ressrf-core/config/domains_aws.json ../../crates/ressrf-core/config/domains_azure.json ../../crates/ressrf-core/config/domains_gcp.json ./config/"
