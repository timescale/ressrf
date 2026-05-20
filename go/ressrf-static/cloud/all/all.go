// Package all is a convenience helper that pulls in every cloud provider
// sub-package and exposes them as a slice. Use this only if you actually
// need every provider's data in your binary; otherwise import the
// specific providers you want directly to keep binary size down (Azure
// alone is ~3.1 MB).
//
//	import (
//	    "github.com/timescale/ressrf/go/ressrf-static"
//	    "github.com/timescale/ressrf/go/ressrf-static/cloud/all"
//	)
//
//	p, _ := ressrfstatic.NewPolicyBuilder(ressrfstatic.PresetExternalOnly).
//	    WithCloudModules(all.Modules()...).
//	    Build()
package all

import (
	"github.com/timescale/ressrf/go/ressrf-static/cloud/aws"
	"github.com/timescale/ressrf/go/ressrf-static/cloud/azure"
	"github.com/timescale/ressrf/go/ressrf-static/cloud/gcp"
	"github.com/timescale/ressrf/go/ressrf-static/cloudmod"
)

// Modules returns every supported cloud provider's CloudModule, in
// stable order (aws, azure, gcp).
func Modules() []cloudmod.Module {
	return []cloudmod.Module{
		aws.Module(),
		azure.Module(),
		gcp.Module(),
	}
}
