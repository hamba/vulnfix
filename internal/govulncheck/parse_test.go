package govulncheck_test

import (
	"os"
	"testing"

	"github.com/hamba/vulnfix/internal/govulncheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFixed(t *testing.T) {
	tests := []struct {
		name string
		file string
		want map[string]string
	}{
		{
			name: "regular module vulnerability",
			file: "testdata/module.json",
			want: map[string]string{
				"example.com/foo": "1.2.3",
			},
		},
		{
			name: "stdlib vulnerability",
			file: "testdata/stdlib.json",
			want: map[string]string{
				"stdlib": "1.22.3",
			},
		},
		{
			name: "toolchain vulnerability",
			file: "testdata/toolchain.json",
			want: map[string]string{
				"toolchain": "1.23.0",
			},
		},
		{
			name: "multiple vulnerabilities picks highest fixed version per module",
			file: "testdata/multi.json",
			want: map[string]string{
				"example.com/foo": "1.3.0",
				"example.com/bar": "2.0.1",
				"stdlib":          "1.22.3",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(test.file)
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close() })

			got, err := govulncheck.ParseFixed(f)

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
