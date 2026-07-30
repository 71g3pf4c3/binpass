// Command binpass is the age-based password manager client, a drop-in
// replacement for pass/gopass.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/71g3pf4c3/binpass/internal/cli"
	versionpkg "github.com/71g3pf4c3/binpass/internal/version"
)

// These variables are overridden at build time via
// -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=...".
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	versionpkg.Version = version
	versionpkg.Commit = commit
	versionpkg.BuildDate = buildDate

	root := cli.NewRootCmd()
	if err := root.ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "binpass:", err)
		os.Exit(1)
	}
}
