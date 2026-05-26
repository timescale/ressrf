// Command gen-data regenerates the IANA + cloud-provider Go source files
// in internal/engine from the workspace's shared Rust-crate config at
// crates/ressrf-core/config (the single source of truth across all
// language bindings).
//
// Run from the go-native/ressrf/ module root:
//
//	go generate ./...
//
// or directly:
//
//	go run ./internal/cmd/gen-data
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"

	"github.com/timescale/ressrf/go-native/ressrf/internal/engine"
)

func main() {
	configDir := flag.String("config", "../../crates/ressrf-core/config", "directory containing ip_ranges.json + domains_*.json (default points at the workspace's shared Rust crate config)")
	outDir := flag.String("out", "internal/engine", "directory to write generated Go files into (relative to repo root)")
	flag.Parse()

	if err := generateIPRanges(*configDir, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "gen-data: ip_ranges: %v\n", err)
		os.Exit(1)
	}
	if err := generateCloud(*configDir, *outDir); err != nil {
		fmt.Fprintf(os.Stderr, "gen-data: cloud: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("gen-data: ip_ranges_generated.go + cloud_generated.go written")
}

// --- ip_ranges ----------------------------------------------------------------

type ipRangesFile struct {
	Description string                  `json:"description"`
	LastUpdated string                  `json:"last_updated"`
	Tiers       map[string]ipRangesTier `json:"tiers"`
}

type ipRangesTier struct {
	Description string          `json:"description"`
	Entries     []ipRangesEntry `json:"entries"`
}

type ipRangesEntry struct {
	CIDR string `json:"cidr"`
	RFC  string `json:"rfc"`
	Name string `json:"name"`
}

// tierOrder is the deterministic emission order. Source-side tiers can come in
// any map iteration order; we always emit IANA v4 then v6 then overrides then
// CSP metadata so the generated file diff is minimal across runs.
//
// `tierConstant` is the engine.DataTier identifier emitted into the generated
// Go source; `tierValue` is the same constant resolved at generator-build time
// so we can call engine.ParseCIDR to validate entries before writing them.
var tierOrder = []struct {
	jsonKey      string
	constant     string
	tierConstant string
	tierValue    engine.DataTier
}{
	{"iana_ipv4", "ianaIPv4Deny", "TierIana", engine.TierIana},
	{"iana_ipv6", "ianaIPv6Deny", "TierIana", engine.TierIana},
	{"override", "overrideDeny", "TierOverride", engine.TierOverride},
	{"csp_metadata", "cspMetadataDeny", "TierCspMetadata", engine.TierCspMetadata},
}

func generateIPRanges(configDir, outDir string) error {
	path := filepath.Join(configDir, "ip_ranges.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var src ipRangesFile
	if err := json.Unmarshal(data, &src); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	var buf bytes.Buffer
	writeHeader(&buf, "ip_ranges.json", src.LastUpdated)
	fmt.Fprintln(&buf, "package engine")
	fmt.Fprintln(&buf)

	for _, t := range tierOrder {
		tier, ok := src.Tiers[t.jsonKey]
		if !ok {
			return fmt.Errorf("missing tier %q in %s", t.jsonKey, path)
		}
		// Validate every CIDR at generator-build time so the runtime
		// mustParseCIDR call in the generated file is guaranteed not to
		// panic on shipped data.
		for _, entry := range tier.Entries {
			if _, err := engine.ParseCIDR(entry.CIDR, t.tierValue); err != nil {
				return fmt.Errorf("invalid CIDR %q in tier %q: %w", entry.CIDR, t.jsonKey, err)
			}
		}
		fmt.Fprintf(&buf, "// %s: %s\n", t.constant, tier.Description)
		fmt.Fprintf(&buf, "var %s = [...]CIDR{\n", t.constant)
		for _, entry := range tier.Entries {
			rfc := entry.RFC
			if rfc == "" {
				rfc = "N/A"
			}
			fmt.Fprintf(&buf, "\tmustParseCIDR(%q, %s), // %s (%s)\n",
				entry.CIDR, t.tierConstant, entry.Name, rfc)
		}
		fmt.Fprintln(&buf, "}")
		fmt.Fprintln(&buf)
	}

	return writeFormatted(filepath.Join(outDir, "ip_ranges_generated.go"), buf.Bytes())
}

// --- cloud --------------------------------------------------------------------

type cloudFile struct {
	Provider              string      `json:"provider"`
	LastUpdated           string      `json:"last_updated"`
	DenyRanges            []cloudCIDR `json:"deny_ranges"`
	DeniedDomainSuffixes  []string    `json:"denied_domain_suffixes"`
	ServiceDomainSuffixes []string    `json:"service_domain_suffixes"`
	// ServiceRanges is the big optional table; we intentionally do not read it
	// because the Go binding has no public API that consumes per-service IP
	// ranges. Mirroring the Rust struct here would balloon the binary by ~5MB.
}

type cloudCIDR struct {
	CIDR string `json:"cidr"`
	Name string `json:"name"`
}

// cloudProviders is the deterministic emission order for the generated file.
var cloudProviders = []struct {
	jsonName string
	constant string // CloudProvider constant in cloud.go
	tier     string // engine.DataTier identifier
}{
	{"aws", "CloudAWS", "TierCloudAws"},
	{"azure", "CloudAzure", "TierCloudAzure"},
	{"gcp", "CloudGCP", "TierCloudGcp"},
}

func generateCloud(configDir, outDir string) error {
	loaded := make(map[string]cloudFile, len(cloudProviders))
	var newestUpdate string
	for _, p := range cloudProviders {
		path := filepath.Join(configDir, "domains_"+p.jsonName+".json")
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var src cloudFile
		if err := json.Unmarshal(data, &src); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		loaded[p.jsonName] = src
		if src.LastUpdated > newestUpdate {
			newestUpdate = src.LastUpdated
		}
	}

	var buf bytes.Buffer
	writeHeader(&buf, "domains_*.json", newestUpdate)
	fmt.Fprintln(&buf, "package engine")
	fmt.Fprintln(&buf)
	fmt.Fprintln(&buf, "// cloudConfigs is built from crates/ressrf-core/config/domains_*.json.")
	fmt.Fprintln(&buf, "// To refresh, run: go generate ./...")
	fmt.Fprintln(&buf, "var cloudConfigs = map[CloudProvider]cloudConfig{")

	for _, p := range cloudProviders {
		src := loaded[p.jsonName]
		fmt.Fprintf(&buf, "\t%s: {\n", p.constant)

		fmt.Fprintln(&buf, "\t\tdenyRanges: []string{")
		for _, c := range src.DenyRanges {
			fmt.Fprintf(&buf, "\t\t\t%q, // %s\n", c.CIDR, c.Name)
		}
		fmt.Fprintln(&buf, "\t\t},")

		writeStringSlice(&buf, "deniedSuffixes", src.DeniedDomainSuffixes)
		writeStringSlice(&buf, "serviceSuffixes", src.ServiceDomainSuffixes)

		fmt.Fprintf(&buf, "\t\ttier: %s,\n", p.tier)
		fmt.Fprintln(&buf, "\t},")
	}
	fmt.Fprintln(&buf, "}")

	return writeFormatted(filepath.Join(outDir, "cloud_generated.go"), buf.Bytes())
}

func writeStringSlice(buf *bytes.Buffer, name string, values []string) {
	// Sort defensively so unsorted upstream input still produces stable output.
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	fmt.Fprintf(buf, "\t\t%s: []string{\n", name)
	for _, v := range sorted {
		fmt.Fprintf(buf, "\t\t\t%q,\n", v)
	}
	fmt.Fprintln(buf, "\t\t},")
}

// --- shared -------------------------------------------------------------------

func writeHeader(buf *bytes.Buffer, src, lastUpdated string) {
	fmt.Fprintln(buf, "// Code generated by ./internal/cmd/gen-data — DO NOT EDIT.")
	fmt.Fprintf(buf, "// Source: crates/ressrf-core/config/%s\n", src)
	if lastUpdated != "" {
		fmt.Fprintf(buf, "// last_updated: %s\n", lastUpdated)
	}
	fmt.Fprintln(buf)
}

func writeFormatted(path string, raw []byte) error {
	formatted, err := format.Source(raw)
	if err != nil {
		// Write the unformatted output so the user can diagnose the syntax
		// error; the file is overwritten on the next successful run.
		_ = os.WriteFile(path, raw, 0o644)
		return fmt.Errorf("gofmt %s: %w", path, err)
	}
	return os.WriteFile(path, formatted, 0o644)
}
