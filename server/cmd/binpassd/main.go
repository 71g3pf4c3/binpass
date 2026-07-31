// Command binpassd is the binpass synchronisation server: authentication,
// end-to-end-encrypted vault storage, and multi-device sync over gRPC + REST.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/71g3pf4c3/binpass/server/config"
	"github.com/71g3pf4c3/binpass/server/internal/app"
)

// Build metadata, injected via -ldflags.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	var (
		configPath  = flag.String("config", "", "path to config.yaml")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("binpassd %s (commit %s, built %s)\n", version, commit, buildDate)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "binpassd: config:", err)
		os.Exit(1)
	}
	cfg.App.Version = version

	if err := app.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "binpassd:", err)
		os.Exit(1)
	}
}
