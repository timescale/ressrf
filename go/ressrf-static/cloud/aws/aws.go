// Package aws exposes the AWS cloud provider's SSRF deny ranges and
// domain suffix data as a [ressrfstatic.CloudModule].
//
// Importing this package adds the AWS JSON blob (~440 KB) to the binary.
// If you don't need AWS, simply don't import this package — the Go
// linker will omit the data entirely. To attach the module:
//
//	import (
//	    "github.com/timescale/ressrf/go/ressrf-static"
//	    "github.com/timescale/ressrf/go/ressrf-static/cloud/aws"
//	)
//
//	p, _ := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
//	    WithCloudModule(aws.Module()).
//	    Build()
package aws

import (
	_ "embed"
	"encoding/json"

	"github.com/timescale/ressrf/go/ressrf-static/cloudmod"
)

//go:embed domains_aws.json
var jsonData []byte

// Module returns the AWS cloud provider's CloudModule. Cheap; the JSON
// is only parsed when the policy is built.
func Module() cloudmod.Module {
	return cloudmod.Module{Name: "aws", JSON: jsonData}
}

// DeniedSuffixes returns the AWS internal DNS suffixes (e.g.
// ".compute.internal", ".internal"). Pipe into
// [ressrfstatic.PolicyBuilder.WithDeniedSuffixes] to also block these
// hostnames at the URL layer (the WASM ABI surface only blocks the
// metadata IPs by default).
func DeniedSuffixes() []string { return parseSuffixes().Denied }

// ServiceSuffixes returns the AWS legitimate-service suffixes (e.g.
// ".amazonaws.com"). Pipe into
// [ressrfstatic.PolicyBuilder.WithTrustedSuffixes] for strict
// allowlist mode.
func ServiceSuffixes() []string { return parseSuffixes().Service }

type suffixes struct {
	Denied  []string `json:"denied_domain_suffixes"`
	Service []string `json:"service_domain_suffixes"`
}

// parseSuffixes decodes the suffix lists from the embedded JSON. Called
// at policy-construction time, not on a hot path, so we don't bother
// caching.
func parseSuffixes() suffixes {
	var s suffixes
	_ = json.Unmarshal(jsonData, &s)
	return s
}
