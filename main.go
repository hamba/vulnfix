// Package main implements the vulnfix command.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/hamba/vulnfix/internal/govulncheck"
	"github.com/hamba/vulnfix/internal/modfix"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	dir := flag.String("C", ".", "change to `dir` before running vulnfix")
	outFile := flag.String("o", "", "write CVE report to `file`")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fixes, err := govulncheck.Parse(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
		return 1
	}

	if len(fixes) == 0 {
		fmt.Fprintln(os.Stderr, "vulnfix: no fixable vulnerabilities found")
		return 0
	}

	versions := make(map[string]string, len(fixes))
	for mod, fix := range fixes {
		versions[mod] = fix.Version
	}
	if err = modfix.Apply(ctx, *dir, versions); err != nil {
		fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
		return 1
	}

	if *outFile != "" && *outFile != "-" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()

		writeReport(f, fixes)
	}
	return 0
}

// writeReport writes a Markdown CVE report for fixes to w.
// Modules and their OSVs are sorted for deterministic output.
func writeReport(w io.Writer, fixes map[string]govulncheck.Fix) {
	modules := make([]string, 0, len(fixes))
	for mod := range fixes {
		modules = append(modules, mod)
	}
	sort.Strings(modules)

	var b strings.Builder
	b.WriteString("# Vulnerability Report\n\n")

	for _, mod := range modules {
		fix := fixes[mod]
		fmt.Fprintf(&b, "## `%s` → `%s`\n\n", mod, fix.Version)

		osvs := fix.OSVs
		sort.Slice(osvs, func(i, j int) bool {
			return osvs[i].ID < osvs[j].ID
		})

		for _, o := range osvs {
			// Heading: OSV ID with optional aliases.
			if len(o.Aliases) > 0 {
				fmt.Fprintf(&b, "### %s (%s)\n\n", o.ID, strings.Join(o.Aliases, ", "))
			} else {
				fmt.Fprintf(&b, "### %s\n\n", o.ID)
			}

			if o.Summary != "" {
				fmt.Fprintf(&b, "%s\n\n", o.Summary)
			}

			if len(o.References) > 0 {
				b.WriteString("**References**\n\n")
				for _, ref := range o.References {
					fmt.Fprintf(&b, "- <%s>\n", ref)
				}
				b.WriteByte('\n')
			}
		}
	}
	_, _ = io.WriteString(w, b.String())
}
