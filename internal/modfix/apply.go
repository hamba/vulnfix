// Package modfix upgrades vulnerable Go module dependencies to their
// minimum fixed versions using the go toolchain.
package modfix

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/hamba/vulnfix/internal/govulncheck"
)

// Apply upgrades each module in fixes to its fixed version by running
// "go get", then cleans up the module graph with "go mod tidy".
// All commands run inside dir. ctx controls cancellation.
func Apply(ctx context.Context, dir string, fixes map[string]string) error {
	for mod, ver := range fixes {
		arg := moduleArg(mod, ver)
		if err := runIn(ctx, dir, "go", "get", arg); err != nil {
			return fmt.Errorf("go get %s: %w", arg, err)
		}
	}

	if err := runIn(ctx, dir, "go", "mod", "tidy"); err != nil {
		return fmt.Errorf("go mod tidy: %w", err)
	}
	return nil
}

// moduleArg returns the argument to pass to "go get" for the given module
// and version. stdlib and toolchain use special go-directive syntax.
func moduleArg(mod, ver string) string {
	switch mod {
	case govulncheck.GoStdModulePath:
		// "go get go@1.22.3" updates the go directive in go.mod.
		return "go@" + ver
	case govulncheck.GoToolchainPath:
		// "go get toolchain@go1.22.3" updates the toolchain directive in go.mod.
		return "toolchain@go" + ver
	default:
		return mod + "@v" + ver
	}
}

func runIn(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
