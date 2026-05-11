// Package report renders a Markdown vulnerability report from a map of module fixes.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hamba/vulnfix/govulncheck"
)

// Write renders a Markdown vulnerability report to w.
// Modules and their OSVs are sorted alphabetically.
func Write(w io.Writer, fixes map[string]govulncheck.Fix) {
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
