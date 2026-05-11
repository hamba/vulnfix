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

const (
	// GoStdModulePath is the pseudo-module path used by govulncheck for
	// standard library vulnerabilities.
	GoStdModulePath = "stdlib"

	// GoToolchainPath is the pseudo-module path used by govulncheck for
	// toolchain vulnerabilities.
	GoToolchainPath = "toolchain"
)

// OSV holds the metadata of one vulnerability that contributed a finding for a module.
type OSV struct {
	// ID is the Go vulnerability database identifier, e.g. "GO-2024-0001".
	ID string

	// Aliases contains alternate identifiers such as CVE or GHSA IDs.
	Aliases []string

	// Summary is a short human-readable description of the vulnerability.
	Summary string

	// References are URLs with more information (advisories, fixes, etc.).
	References []string
}

// Fix describes the upgrade needed for one module and the vulnerabilities it resolves.
type Fix struct {
	// Version is the minimum version that fixes all reachable vulnerabilities
	// for this module, including its natural prefix: "v1.2.3" for regular
	// modules, "go1.22.3" for stdlib, "go1.23.0" for toolchain.
	Version string

	// OSVs are the vulnerabilities that had actual findings against this module.
	OSVs []OSV
}

// Parse reads govulncheck -json output from r and returns a map of module path
// to Fix. Only finding messages are considered; modules whose vulnerable
// symbols are never called are not included.
func Parse(r io.Reader) (map[string]Fix, error) {
	dec := json.NewDecoder(r)

	osvs := map[string]*osvEntry{}
	fixes := map[string]Fix{}

	for {
		var msg message
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parsing govulncheck JSON: %w", err)
		}

		if msg.OSV != nil {
			osvs[msg.OSV.ID] = msg.OSV
		}

		if msg.Finding == nil || len(msg.Finding.Trace) == 0 {
			continue
		}

		mod := msg.Finding.Trace[0].Module
		ver := msg.Finding.FixedVersion // keep natural prefix ("v..." or "go...")

		f := fixes[mod]
		if f.Version == "" || semver.Compare("v"+normalizeVersion(ver), "v"+normalizeVersion(f.Version)) > 0 {
			f.Version = ver
		}

		osvID := msg.Finding.OSV
		if !hasOSV(f.OSVs, osvID) {
			o := OSV{ID: osvID}
			if entry, ok := osvs[osvID]; ok {
				o.Aliases = entry.Aliases
				o.Summary = entry.Summary
				for _, ref := range entry.References {
					o.References = append(o.References, ref.URL)
				}
			}
			f.OSVs = append(f.OSVs, o)
		}

		fixes[mod] = f
	}

	return fixes, nil
}

func hasOSV(osvs []OSV, id string) bool {
	for _, o := range osvs {
		if o.ID == id {
			return true
		}
	}
	return false
}

func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "go")
	return v
}

// These types implement the govulncheck -json message protocol.
// The JSON tags mirror golang.org/x/vuln/internal/govulncheck and
// golang.org/x/vuln/internal/osv, which are not importable externally.

type message struct {
	Finding *finding  `json:"finding"`
	OSV     *osvEntry `json:"osv"`
}

type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

type frame struct {
	Module string `json:"module"`
}

type osvEntry struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases"`
	Summary    string   `json:"summary"`
	References []osvRef `json:"references"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
