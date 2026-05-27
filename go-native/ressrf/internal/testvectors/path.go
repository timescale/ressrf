// Package testvectors loads JSON files from the workspace's shared
// tests/vectors/ directory, the canonical cross-language conformance
// source. Tests across multiple packages call Read instead of hand-rolling
// the filepath walk up out of the Go module.
package testvectors

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Read returns the bytes of <repo-root>/tests/vectors/<name>.
func Read(name string) ([]byte, error) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("testvectors: cannot resolve source location")
	}
	// here = <repo-root>/go-native/ressrf/internal/testvectors/path.go
	return os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "tests", "vectors", name))
}
