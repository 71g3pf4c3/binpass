package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/spf13/cobra"
)

// newRecryptCmd builds `binpass recrypt`.
func newRecryptCmd(app *App) *cobra.Command {
	var path string
	var useAge, useGPG, dryRun bool
	cmd := &cobra.Command{
		Use:     "recrypt [--age|--gpg] [--path=subfolder,-p subfolder] [--dry-run]",
		Aliases: []string{"reencrypt"},
		Short:   "Reencrypt every entry for the chosen backend",
		Long: `Reencrypt every entry under the store, or --path, for the chosen backend.

Entries in the other format are rewritten in the target one: --age turns
.gpg files into .age files, --gpg the other way round. Entries already in
the target format are rewritten for the current recipients file, so adding
a recipient and running recrypt re-keys the whole store. Without a flag the
configured default backend is the target.

A missing recipients file for the target backend is refused up front
rather than on the first entry; run init first in that case. An interrupted
run can simply be run again: each entry is rewritten before its old file
is removed, and the second pass picks up where the first stopped.

--dry-run lists what would change without touching the store.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			kind := app.Cfg.Default
			switch {
			case useAge && useGPG:
				return fmt.Errorf("Error: choose either --age or --gpg, not both.") //nolint:revive,staticcheck // diagnostic style.
			case useAge:
				kind = config.BackendAge
			case useGPG:
				kind = config.BackendGPG
			}
			return app.runRecrypt(path, kind, dryRun)
		},
	}
	cmd.Flags().StringVarP(&path, "path", "p", "", "reencrypt a subfolder only")
	cmd.Flags().BoolVar(&useAge, "age", false, "reencrypt into the age backend")
	cmd.Flags().BoolVar(&useGPG, "gpg", false, "reencrypt into the GPG backend")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be reencrypted without writing")
	return cmd
}

// runRecrypt reencrypts every entry under sub for the kind backend, or
// reports what it would do when dryRun is set.
func (a *App) runRecrypt(sub string, kind config.Backend, dryRun bool) error {
	s, err := a.Store()
	if err != nil {
		return err
	}
	target, err := a.cryptoFor(kind)
	if err != nil {
		return err
	}
	// Recipients are read per directory while writing; a missing file at
	// the root would fail the first entry mid-store, leaving a half-run
	// for no reason. Refusing before touching anything names the fix.
	if _, err := os.Stat(filepath.Join(s.Dir(), sub, target.RecipientsFile())); err != nil {
		return fmt.Errorf("no %s in %s for the %s backend: run binpass init first",
			target.RecipientsFile(), s.Dir(), kind)
	}
	infos, err := s.EntryInfos(sub)
	if err != nil {
		return err
	}
	changes := 0
	for _, e := range infos {
		if e.Ext != target.Ext() {
			changes++
		}
	}
	if dryRun {
		fmt.Fprintf(a.Out, "Would reencrypt %d entries for the %s backend (%d changing format)\n",
			len(infos), kind, changes)
		for _, e := range infos {
			if e.Ext != target.Ext() {
				fmt.Fprintf(a.Out, "  %s: %s -> %s\n", e.Name, e.Ext, target.Ext())
			}
		}
		return nil
	}
	if err := s.Reencrypt(sub, target); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Reencrypted %d entries for the %s backend (%d changed format)\n",
		len(infos), kind, changes)
	return nil
}
