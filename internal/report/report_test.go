package report_test

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/hamba/vulnfix/internal/govulncheck"
	"github.com/hamba/vulnfix/internal/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestWrite(t *testing.T) {
	tests := []struct {
		name       string
		goldenFile string
		fixes      map[string]govulncheck.Fix
	}{
		{
			name:       "multiple modules and OSVs are sorted alphabetically",
			goldenFile: "testdata/multi.md.golden",
			fixes: map[string]govulncheck.Fix{
				"stdlib": {
					Version: "go1.22.3",
					OSVs: []govulncheck.OSV{
						{
							ID:         "GO-2024-0002",
							Aliases:    []string{"CVE-2024-99999"},
							Summary:    "HTTP/2 server memory exhaustion in stdlib",
							References: []string{"https://pkg.go.dev/vuln/GO-2024-0002"},
						},
					},
				},
				"example.com/foo": {
					Version: "v1.3.0",
					OSVs: []govulncheck.OSV{
						{
							ID:         "GO-2024-0004",
							Aliases:    []string{"CVE-2024-12346"},
							Summary:    "Denial of service in example.com/foo",
							References: []string{"https://pkg.go.dev/vuln/GO-2024-0004"},
						},
						{
							ID:         "GO-2024-0001",
							Aliases:    []string{"CVE-2024-12345"},
							Summary:    "Remote code execution via crafted input in example.com/foo",
							References: []string{"https://pkg.go.dev/vuln/GO-2024-0001"},
						},
					},
				},
				"example.com/bar": {
					Version: "v2.0.1",
					OSVs: []govulncheck.OSV{
						{
							ID:         "GO-2024-0005",
							Aliases:    []string{"CVE-2024-77777"},
							Summary:    "SQL injection in example.com/bar",
							References: []string{"https://pkg.go.dev/vuln/GO-2024-0005"},
						},
					},
				},
			},
		},
		{
			name:       "OSV without aliases omits the parenthetical",
			goldenFile: "testdata/no_aliases.md.golden",
			fixes: map[string]govulncheck.Fix{
				"example.com/foo": {
					Version: "v1.2.3",
					OSVs: []govulncheck.OSV{
						{
							ID:         "GO-2024-0001",
							Summary:    "Remote code execution via crafted input in example.com/foo",
							References: []string{"https://pkg.go.dev/vuln/GO-2024-0001"},
						},
					},
				},
			},
		},
		{
			name:       "OSV without summary or references renders only the heading",
			goldenFile: "testdata/no_summary_no_references.md.golden",
			fixes: map[string]govulncheck.Fix{
				"example.com/foo": {
					Version: "v1.2.3",
					OSVs: []govulncheck.OSV{
						{
							ID:      "GO-2024-0001",
							Aliases: []string{"CVE-2024-12345"},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var buf strings.Builder
			report.Write(&buf, test.fixes)
			got := buf.String()

			if *update {
				require.NoError(t, os.WriteFile(test.goldenFile, []byte(got), 0o644))
				return
			}

			wantBytes, err := os.ReadFile(test.goldenFile)
			require.NoError(t, err)

			assert.Equal(t, string(wantBytes), got)
		})
	}
}
