// Package e2e drives the binpass command line through testscript scenarios.
//
// The scenarios in testdata are plain text: a sequence of commands with their
// expected output. They run the real binary against a real store, but use age
// rather than GPG, so a full run needs no keyring and no agent.
package e2e

import (
	"fmt"
	"os"
	"testing"

	"filippo.io/age"
	"github.com/71g3pf4c3/binpass/internal/cli"
	"github.com/rogpeppe/go-internal/testscript"
)

// TestMain registers binpass as a command testscript can invoke directly,
// which keeps every scenario in-process and therefore fast.
func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"binpass": func() { os.Exit(cli.Execute("test", "none", "unknown")) },
	})
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata",
		Setup: func(env *testscript.Env) error {
			// Each scenario gets a fresh identity and a store that knows
			// nothing about the developer's own configuration.
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return err
			}
			keyFile := env.WorkDir + "/identity.key"
			if err := os.WriteFile(keyFile, []byte(id.String()+"\n"), 0o600); err != nil {
				return err
			}
			env.Setenv("BINPASS_IDENTITY", keyFile)
			env.Setenv("BINPASS_CONFIG", env.WorkDir+"/nonexistent.yaml")
			env.Setenv("PASSWORD_STORE_DIR", env.WorkDir+"/store")
			env.Setenv("RECIPIENT", id.Recipient().String())
			// Pin tree's rendering inputs so scenarios can assert on exact
			// output regardless of the host locale.
			env.Setenv("LC_ALL", "C.UTF-8")
			env.Setenv("TERM", "")
			return nil
		},
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			// countlines asserts how many lines a file has, which is how the
			// generated-password scenarios check length without printing it.
			"countlines": func(ts *testscript.TestScript, neg bool, args []string) {
				if len(args) != 2 {
					ts.Fatalf("usage: countlines file n")
				}
				data := ts.ReadFile(args[0])
				n := 0
				for _, c := range data {
					if c == '\n' {
						n++
					}
				}
				want := args[1]
				got := fmt.Sprint(n)
				if (got == want) == neg {
					ts.Fatalf("%s has %s lines, want %s", args[0], got, want)
				}
			},
		},
	})
}
