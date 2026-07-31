// Package e2e runs end-to-end CLI scenarios with rogpeppe/go-internal's
// testscript. Each testdata/*.txtar file drives the real binpass binary
// through a scripted session, asserting on stdout, stderr, and files.
package e2e

import (
	"fmt"
	"os"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/cli"
	"github.com/rogpeppe/go-internal/testscript"
)

// TestMain registers a "binpass" command implemented by the real CLI so the
// scripts invoke the same code paths as the shipped binary.
func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"binpass": func() int {
			root := cli.NewRootCmd()
			root.SetArgs(cli.NormalizeArgs(os.Args[1:]))
			if err := root.Execute(); err != nil {
				fmt.Fprintln(os.Stderr, "binpass:", err)
				return 1
			}
			return 0
		},
	}))
}

// TestScripts runs every testdata script.
func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			// Isolate store and config under the script's work dir.
			env.Setenv("BINPASS_STORE_DIR", env.Getenv("WORK")+"/store")
			env.Setenv("XDG_CONFIG_HOME", env.Getenv("WORK")+"/config")
			// Neutralise inherited pass env so scripts are deterministic.
			env.Setenv("PASSWORD_STORE_DIR", "")
			env.Setenv("PASSWORD_STORE_CLIP_TIME", "")
			env.Setenv("PASSWORD_STORE_GENERATED_LENGTH", "")
			return nil
		},
	})
}
