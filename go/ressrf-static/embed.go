package ressrfstatic

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed config/ip_ranges.json
var ipRangesJSON []byte

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

// CloudFile is the parsed shape of a domains_{provider}.json file. Each
// cloud sub-package (cloud/aws, cloud/azure, cloud/gcp) embeds its own
// JSON and parses it into this shape via ParseCloudFile.
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

// ParseCloudFile decodes the JSON payload carried by a CloudModule.
// Called once per Build() by applyCloudModule; sub-packages return the
// raw bytes via Module().JSON and let the main package own parsing so
// schema changes don't have to propagate to every cloud package.
func ParseCloudFile(raw []byte) (*CloudFile, error) {
	var c CloudFile
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("ressrfstatic: parse cloud file: %w", err)
	}
	return &c, nil
}
