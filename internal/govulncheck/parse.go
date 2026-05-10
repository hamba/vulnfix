// Package govulncheck reads the JSON output produced by govulncheck -json
// and extracts the minimum fixed version for each vulnerable module.
package govulncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/mod/semver"
)

// These types implement the govulncheck -json message protocol.
// The JSON tags mirror golang.org/x/vuln/internal/govulncheck and
// golang.org/x/vuln/internal/osv, which are not importable externally.

type message struct {
	OSV *osvEntry `json:"osv,omitempty"`
}

type osvEntry struct {
	Affected []affected `json:"affected"`
}

type affected struct {
	Package osvModule `json:"package"`
	Ranges  []rng     `json:"ranges"`
}

// osvModule is the package identifier in an OSV entry.
// The JSON field name is "name", not "path".
type osvModule struct {
	Path string `json:"name"`
}

type rng struct {
	Events []rangeEvent `json:"events"`
}

type rangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

const (
	// GoStdModulePath is the pseudo-module path used by govulncheck for
	// standard library vulnerabilities.
	GoStdModulePath = "stdlib"

	// GoToolchainPath is the pseudo-module path used by govulncheck for
	// toolchain vulnerabilities.
	GoToolchainPath = "toolchain"
)

// ParseFixed reads govulncheck -json output from r and returns a map of
// module path to the minimum version that fixes all known vulnerabilities
// for that module. When a module appears in multiple OSV entries the
// highest fix version wins. Versions have no leading "v".
//
//nolint:gocognit // Splitting this will not make it simpler.
func ParseFixed(r io.Reader) (map[string]string, error) {
	dec := json.NewDecoder(r)

	fixed := map[string]string{}
	for {
		var msg message
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parsing govulncheck JSON: %w", err)
		}
		if msg.OSV == nil {
			continue
		}

		for _, aff := range msg.OSV.Affected {
			mod := aff.Package.Path
			if mod == "" {
				continue
			}

			for _, r := range aff.Ranges {
				for _, ev := range r.Events {
					if ev.Fixed == "" {
						continue
					}

					// semver.Compare expects a leading "v".
					candidate := "v" + ev.Fixed
					if existing, ok := fixed[mod]; !ok || semver.Compare(candidate, "v"+existing) > 0 {
						fixed[mod] = ev.Fixed
					}
				}
			}
		}
	}
	return fixed, nil
}
