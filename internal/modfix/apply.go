// Package modfix upgrades vulnerable Go module dependencies to their
// minimum fixed versions using the go toolchain.
package modfix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Apply upgrades each module in fixes to its fixed version by running
// "go get", then cleans up the module graph with "go mod tidy".
// fixes is a map of module path to the minimum fixed version.
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

func moduleArg(mod, ver string) string {
	switch mod {
	case "stdlib":
		// ver is "go1.22.3"; "go get go@1.22.3" updates the go directive in go.mod.
		return "go@" + strings.TrimPrefix(ver, "go")
	case "toolchain":
		// ver is "go1.23.0"; "go get toolchain@go1.23.0" updates the toolchain directive.
		return "toolchain@" + ver
	default:
		// ver is "v1.2.3".
		return mod + "@" + ver
	}
}

func runIn(ctx context.Context, dir, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
