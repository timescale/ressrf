package engine

// CloudProvider names one of the supported metadata-aware providers. The
// cloudConfigs map that defines each provider's deny CIDRs and domain
// suffixes lives in cloud_generated.go and is regenerated from
// crates/ressrf-core/config/domains_*.json by ./internal/cmd/gen-data.
type CloudProvider string

const (
	CloudAWS   CloudProvider = "aws"
	CloudAzure CloudProvider = "azure"
	CloudGCP   CloudProvider = "gcp"
)

// cloudConfig captures the small subset of crates/ressrf-core/config/domains_*.json
// that the policy engine actually uses (deny CIDRs + denied/service domain
// suffixes). The full JSON also carries `service_ranges`, which the Go
// binding's public API never consumed, so it is intentionally omitted by the
// generator.
type cloudConfig struct {
	denyRanges      []string
	deniedSuffixes  []string
	serviceSuffixes []string
	tier            DataTier
}

// CloudProviderDenyRanges returns the metadata-endpoint CIDR strings for a
// given provider, or nil if the name is unknown. Names are case-sensitive
// lowercase to match the Rust side.
func CloudProviderDenyRanges(name string) []string {
	cfg, ok := cloudConfigs[CloudProvider(name)]
	if !ok {
		return nil
	}
	return cfg.denyRanges
}

// CloudProviderDeniedSuffixes returns the internal DNS suffixes a provider
// reserves (used by the URI validator to block internal hostnames).
func CloudProviderDeniedSuffixes(name string) []string {
	cfg, ok := cloudConfigs[CloudProvider(name)]
	if !ok {
		return nil
	}
	return cfg.deniedSuffixes
}

// CloudProviderServiceSuffixes returns the legitimate service domain suffixes
// for a provider (used to opt cloud APIs out of a `denied_suffixes` rule).
func CloudProviderServiceSuffixes(name string) []string {
	cfg, ok := cloudConfigs[CloudProvider(name)]
	if !ok {
		return nil
	}
	return cfg.serviceSuffixes
}

// CloudProviderTier returns the DataTier label for entries added by a given
// provider; unknown providers map to TierUserDeny.
func CloudProviderTier(name string) DataTier {
	cfg, ok := cloudConfigs[CloudProvider(name)]
	if !ok {
		return TierUserDeny
	}
	return cfg.tier
}
