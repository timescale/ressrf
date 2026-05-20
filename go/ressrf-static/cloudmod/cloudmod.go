// Package cloudmod defines the CloudModule value type produced by every
// cloud provider sub-package under
// github.com/timescale/ressrf/go/ressrf-static/cloud/*.
//
// It lives in its own package — separate from ressrf-static — so the
// provider sub-packages have a stable dependency target that doesn't
// import the main package. That keeps the dependency graph acyclic so
// the main package's internal tests can import the provider
// sub-packages.
//
// Callers shouldn't need to use this package directly: ressrf-static
// re-exports the type as ressrfstatic.CloudModule via a type alias.
package cloudmod

// Module carries a cloud provider's raw JSON payload. The Name is the
// provider's stable identifier (e.g. "aws"), surfaced in audit events.
// JSON is the bytes of the provider's domains_{name}.json file, parsed
// once at Policy build time.
type Module struct {
	Name string
	JSON []byte
}
