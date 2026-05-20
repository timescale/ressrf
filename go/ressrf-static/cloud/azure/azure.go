// Package azure exposes the Azure cloud provider's SSRF deny ranges and
// domain suffix data as a [ressrfstatic.CloudModule].
//
// Importing this package adds the Azure JSON blob (~3.1 MB — by far the
// largest provider dataset) to the binary. If you don't need Azure,
// simply don't import this package — the Go linker will omit the data
// entirely.
//
//	import (
//	    "github.com/timescale/ressrf/go/ressrf-static"
//	    "github.com/timescale/ressrf/go/ressrf-static/cloud/azure"
//	)
//
//	p, _ := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
//	    WithCloudModule(azure.Module()).
//	    Build()
package azure

import (
	_ "embed"
	"encoding/json"

	"github.com/timescale/ressrf/go/ressrf-static/cloudmod"
)

//go:embed domains_azure.json
var jsonData []byte

// Module returns the Azure cloud provider's CloudModule.
func Module() cloudmod.Module {
	return cloudmod.Module{Name: "azure", JSON: jsonData}
}

// DeniedSuffixes returns Azure internal DNS suffixes. Pipe into
// [ressrfstatic.PolicyBuilder.WithDeniedSuffixes].
func DeniedSuffixes() []string { return parseSuffixes().Denied }

// ServiceSuffixes returns Azure legitimate-service suffixes (e.g.
// ".core.windows.net"). Pipe into
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
