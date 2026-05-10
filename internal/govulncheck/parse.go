// Package govulncheck reads the JSON output produced by govulncheck -json
// and extracts the minimum fixed version for each vulnerable module.
package govulncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/mod/semver"
)

// These types implement the govulncheck -json message protocol.
// The JSON tags mirror golang.org/x/vuln/internal/govulncheck and
// golang.org/x/vuln/internal/osv, which are not importable externally.

type message struct {
	Finding *finding `json:"finding"`
}

type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

type frame struct {
	Module string `json:"module"`
}

const (
	// GoStdModulePath is the pseudo-module path used by govulncheck for
	// standard library vulnerabilities.
	GoStdModulePath = "stdlib"

	// GoToolchainPath is the pseudo-module path used by govulncheck for
	// toolchain vulnerabilities.
	GoToolchainPath = "toolchain"
)

// ParseFixed reads govulncheck -json output from r and returns a map of module
// path to the minimum version that fixes all reachable vulnerabilities. Only
// finding messages are considered, so modules that are imported but whose
// vulnerable symbols are never called are not included. When a module has
// multiple findings the highest fix version is used. Versions have no leading "v".
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

		if msg.Finding == nil || len(msg.Finding.Trace) == 0 {
			continue
		}

		mod := msg.Finding.Trace[0].Module
		fixedVer := msg.Finding.FixedVersion
		fixedVer = strings.TrimPrefix(fixedVer, "v")
		fixedVer = strings.TrimPrefix(fixedVer, "go")
		if existing, ok := fixed[mod]; !ok || semver.Compare("v"+fixedVer, "v"+existing) > 0 {
			fixed[mod] = fixedVer
		}
	}
	return fixed, nil
}
