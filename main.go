// Package main implements the vulnfix command.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hamba/vulnfix/govulncheck"
	"github.com/hamba/vulnfix/modfix"
	"github.com/hamba/vulnfix/report"
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
		_, _ = fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
		return 1
	}

	if len(fixes) == 0 {
		if *outFile != "" && *outFile != "-" {
			f, err := os.Create(*outFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
				return 1
			}
			defer func() { _ = f.Close() }()

			_, _ = f.WriteString("# Vulnerability Report\n\nNo vulnerabilities found.\n")
		}

		_, _ = fmt.Fprintln(os.Stdout, "vulnfix: no fixable vulnerabilities found")
		return 0
	}

	versions := make(map[string]string, len(fixes))
	for mod, fix := range fixes {
		versions[mod] = fix.Version
	}
	if err = modfix.Apply(ctx, *dir, versions); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
		return 1
	}

	if *outFile != "" && *outFile != "-" {
		f, err := os.Create(*outFile)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "vulnfix: %v\n", err)
			return 1
		}
		defer func() { _ = f.Close() }()

		report.Write(f, fixes)
	}
	return 0
}
