// Command binpass is a pass(1)-compatible password manager.
package main

import (
	"os"

	"github.com/71g3pf4c3/binpass/internal/cli"
)

// Build metadata, set through -ldflags at release time.
var (
	// version is the release version.
	version = "dev"
	// commit is the git revision the binary was built from.
	commit = "none"
	// buildDate is the build timestamp.
	buildDate = "unknown"
)

func main() {
	os.Exit(cli.Execute(version, commit, buildDate))
}
