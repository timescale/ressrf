package engine

// The slices that drive the default deny list (ianaIPv4Deny, ianaIPv6Deny,
// overrideDeny, cspMetadataDeny) live in ip_ranges_generated.go and are
// regenerated from the workspace's shared Rust-crate config at
// ../../../../crates/ressrf-core/config (single source of truth across all
// language bindings) by ./internal/cmd/gen-data. To refresh, run
// `go generate ./...`.

//go:generate go run ../cmd/gen-data -config ../../../../crates/ressrf-core/config -out .

// mustParseCIDR is the helper the generated files use to build pre-parsed
// CIDR literals at package init. ./internal/cmd/gen-data validates every
// string against ParseCIDR at build time, so a panic here would indicate a
// generator bug rather than a runtime condition.
func mustParseCIDR(s string, tier DataTier) CIDR {
	c, err := ParseCIDR(s, tier)
	if err != nil {
		panic("ressrf: bad generated CIDR " + s + ": " + err.Error())
	}
	return c
}

// DefaultDenySet returns a copy of the IANA + override + CSP-metadata deny
// ranges. The underlying CIDRs are pre-parsed at package init by the
// generated arrays in ip_ranges_generated.go; this function only allocates
// the per-caller slice.
func DefaultDenySet() []CIDR {
	out := make([]CIDR, 0,
		len(ianaIPv4Deny)+len(ianaIPv6Deny)+len(overrideDeny)+len(cspMetadataDeny),
	)
	out = append(out, ianaIPv4Deny[:]...)
	out = append(out, ianaIPv6Deny[:]...)
	out = append(out, overrideDeny[:]...)
	out = append(out, cspMetadataDeny[:]...)
	return out
}
