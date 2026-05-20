// Package gcp exposes the GCP cloud provider's SSRF deny ranges and
// domain suffix data as a [ressrfstatic.CloudModule].
//
// Importing this package adds the GCP JSON blob (~28 KB) to the binary.
// If you don't need GCP, simply don't import this package — the Go
// linker will omit the data entirely.
//
//	import (
//	    "github.com/timescale/ressrf/go/ressrf-static"
//	    "github.com/timescale/ressrf/go/ressrf-static/cloud/gcp"
//	)
//
//	p, _ := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
//	    WithCloudModule(gcp.Module()).
//	    Build()
package gcp

import (
	_ "embed"
	"encoding/json"

	"github.com/timescale/ressrf/go/ressrf-static/cloudmod"
)

//go:embed domains_gcp.json
var jsonData []byte

// Module returns the GCP cloud provider's CloudModule.
func Module() cloudmod.Module {
	return cloudmod.Module{Name: "gcp", JSON: jsonData}
}

// DeniedSuffixes returns GCP internal DNS suffixes (e.g. ".internal"). Pipe
// into [ressrfstatic.PolicyBuilder.WithDeniedSuffixes].
func DeniedSuffixes() []string { return parseSuffixes().Denied }

// ServiceSuffixes returns GCP legitimate-service suffixes (e.g.
// ".googleapis.com"). Pipe into
// [ressrfstatic.PolicyBuilder.WithTrustedSuffixes].
func ServiceSuffixes() []string { return parseSuffixes().Service }

type suffixes struct {
	Denied  []string `json:"denied_domain_suffixes"`
	Service []string `json:"service_domain_suffixes"`
}

func parseSuffixes() suffixes {
	var s suffixes
	_ = json.Unmarshal(jsonData, &s)
	return s
}
