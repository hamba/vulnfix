package govulncheck_test

import (
	"os"
	"testing"

	"github.com/hamba/vulnfix/govulncheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_ParsesFixes(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantMod string
		wantVer string
	}{
		{
			name:    "regular module vulnerability",
			file:    "testdata/module.json",
			wantMod: "example.com/foo",
			wantVer: "v1.2.3",
		},
		{
			name:    "stdlib vulnerability",
			file:    "testdata/stdlib.json",
			wantMod: "stdlib",
			wantVer: "go1.22.3",
		},
		{
			name:    "toolchain vulnerability",
			file:    "testdata/toolchain.json",
			wantMod: "toolchain",
			wantVer: "go1.23.0",
		},
		{
			name:    "multiple vulnerabilities picks highest fixed version per module",
			file:    "testdata/multi.json",
			wantMod: "example.com/foo",
			wantVer: "v1.3.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(test.file)
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close() })

			fixes, err := govulncheck.Parse(f)

			require.NoError(t, err)
			require.Contains(t, fixes, test.wantMod)
			assert.Equal(t, test.wantVer, fixes[test.wantMod].Version)
		})
	}
}

func TestParse_MultipleVulnerabilities(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/multi.json")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	fixes, err := govulncheck.Parse(f)

	require.NoError(t, err)

	// Each module carries its highest fixed version with its natural prefix.
	assert.Equal(t, "v1.3.0", fixes["example.com/foo"].Version)
	assert.Equal(t, "v2.0.1", fixes["example.com/bar"].Version)
	assert.Equal(t, "go1.22.3", fixes["stdlib"].Version)

	// example.com/foo has two contributing OSVs.
	fooOSVs := fixes["example.com/foo"].OSVs
	require.Len(t, fooOSVs, 2)
	ids := []string{fooOSVs[0].ID, fooOSVs[1].ID}
	assert.ElementsMatch(t, []string{"GO-2024-0001", "GO-2024-0004"}, ids)

	// stdlib and bar each have exactly one contributing OSV.
	require.Len(t, fixes["stdlib"].OSVs, 1)
	assert.Equal(t, "GO-2024-0002", fixes["stdlib"].OSVs[0].ID)

	require.Len(t, fixes["example.com/bar"].OSVs, 1)
	assert.Equal(t, "GO-2024-0005", fixes["example.com/bar"].OSVs[0].ID)
}

func TestParse_OSVMetadata(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/module.json")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	fixes, err := govulncheck.Parse(f)

	require.NoError(t, err)
	require.Contains(t, fixes, "example.com/foo")

	osv := fixes["example.com/foo"].OSVs[0]
	assert.Equal(t, "GO-2024-0001", osv.ID)
	assert.Equal(t, []string{"CVE-2024-12345", "GHSA-aaaa-bbbb-cccc"}, osv.Aliases)
	assert.Equal(t, "Remote code execution via crafted input in example.com/foo", osv.Summary)
	assert.Contains(t, osv.References, "https://pkg.go.dev/vuln/GO-2024-0001")
	assert.Contains(t, osv.References, "https://www.cve.org/CVERecord?id=CVE-2024-12345")
}
