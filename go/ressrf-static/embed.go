package ressrfstatic

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed config/ip_ranges.json
var ipRangesJSON []byte

//go:embed config/domains_aws.json
var awsJSON []byte

//go:embed config/domains_azure.json
var azureJSON []byte

//go:embed config/domains_gcp.json
var gcpJSON []byte

// CIDREntry is one row in an IP-range tier. Schema matches the canonical
// crates/ressrf-core/config/ip_ranges.json — fields are optional metadata
// preserved for audit messages.
type CIDREntry struct {
	CIDR string `json:"cidr"`
	RFC  string `json:"rfc,omitempty"`
	Name string `json:"name,omitempty"`
}

// Tier groups CIDR entries by source (IANA, override, CSP metadata).
type Tier struct {
	Description string      `json:"description"`
	Entries     []CIDREntry `json:"entries"`
}

// IPRangesFile is the parsed shape of config/ip_ranges.json.
type IPRangesFile struct {
	SchemaVersion int      `json:"schema_version"`
	Description   string   `json:"description"`
	Sources       []string `json:"sources"`
	LastUpdated   string   `json:"last_updated"`
	Tiers         struct {
		IANAIPv4    Tier `json:"iana_ipv4"`
		IANAIPv6    Tier `json:"iana_ipv6"`
		Override    Tier `json:"override"`
		CSPMetadata Tier `json:"csp_metadata"`
	} `json:"tiers"`
}

// CloudDenyRange is a single deny CIDR for a cloud provider with optional name.
type CloudDenyRange struct {
	CIDR string `json:"cidr"`
	Name string `json:"name,omitempty"`
}

// CloudServiceRanges holds the upstream service-IP prefix data keyed by service.
type CloudServiceRanges struct {
	SyncToken any                 `json:"sync_token,omitempty"`
	Prefixes  map[string][]string `json:"prefixes"`
}

// CloudFile is the parsed shape of config/domains_{aws,azure,gcp}.json.
type CloudFile struct {
	Provider              string             `json:"provider"`
	LastUpdated           string             `json:"last_updated"`
	DenyRanges            []CloudDenyRange   `json:"deny_ranges"`
	DeniedDomainSuffixes  []string           `json:"denied_domain_suffixes"`
	ServiceDomainSuffixes []string           `json:"service_domain_suffixes"`
	ServiceRanges         CloudServiceRanges `json:"service_ranges"`
}

// LoadIPRanges parses the embedded IANA + override deny tiers.
func LoadIPRanges() (*IPRangesFile, error) {
	var f IPRangesFile
	if err := json.Unmarshal(ipRangesJSON, &f); err != nil {
		return nil, fmt.Errorf("ressrfstatic: parse ip_ranges.json: %w", err)
	}
	return &f, nil
}

// LoadCloud parses the embedded data for a known cloud provider.
// Valid names: "aws", "azure", "gcp".
func LoadCloud(name string) (*CloudFile, error) {
	var raw []byte
	switch name {
	case "aws":
		raw = awsJSON
	case "azure":
		raw = azureJSON
	case "gcp":
		raw = gcpJSON
	default:
		return nil, fmt.Errorf("ressrfstatic: unknown cloud provider %q", name)
	}
	var f CloudFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("ressrfstatic: parse domains_%s.json: %w", name, err)
	}
	return &f, nil
}
