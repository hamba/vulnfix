package modfix_test

import (
	"context"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/hamba/vulnfix/modfix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func TestApply(t *testing.T) {
	// Copy testdata/apply into a temp directory so we don't mutate the source.
	tmpDir := t.TempDir()
	copyDir(t, "testdata/apply", tmpDir)

	fixes := map[string]string{
		"stdlib":           "go1.22.3",
		"toolchain":        "go1.23.0",
		"golang.org/x/mod": "v0.8.0",
	}

	err := modfix.Apply(context.Background(), tmpDir, fixes)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(tmpDir, "go.mod"))
	require.NoError(t, err)

	const goldenFile = "testdata/apply/go.mod.golden"

	if *update {
		require.NoError(t, os.WriteFile(goldenFile, got, 0o644))
		return
	}

	want, err := os.ReadFile(goldenFile)
	require.NoError(t, err)

	assert.Equal(t, string(want), string(got))
}

// copyDir copies all regular files from src into dst (non-recursively).
func copyDir(t *testing.T, src, dst string) {
	t.Helper()

	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, d.Name()), data, 0o644)
	})
	require.NoError(t, err)
}
