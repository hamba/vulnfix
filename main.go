// Package main implements the vulnfix command.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hamba/vulnfix/internal/govulncheck"
	"github.com/hamba/vulnfix/internal/modfix"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	dir := flag.String("C", ".", "change to `dir` before running vulnfix")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fixes, err := govulncheck.ParseFixed(os.Stdin)
	if err != nil {
		fmt.Printf("vulnfix: %v", err)
		return 1
	}

	if len(fixes) == 0 {
		fmt.Println("vulnfix: no fixable vulnerabilities found")
		return 0
	}

	if err = modfix.Apply(ctx, *dir, fixes); err != nil {
		fmt.Printf("vulnfix: %v", err)
		return 1
	}
	return 0
}
