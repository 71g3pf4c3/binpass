package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/71g3pf4c3/binpass/pkg/crypto"
	"github.com/71g3pf4c3/binpass/pkg/plugin"
)

// trustStateName is the file recording the parts of a store that decide who
// can read it and what it can run.
//
// It lives in the state directory rather than the store: nothing app-owned
// belongs inside the store, and a record kept there would be rewritten by
// the same remote it exists to catch.
const trustStateName = "trust.json"

// trustState is that record.
type trustState struct {
	// Recipients maps each recipients file to the recipients it listed.
	Recipients crypto.RecipientSets `json:"recipients"`
	// Plugins maps each plugin inside the store to a digest of what
	// running it would do.
	Plugins plugin.StoreSnapshot `json:"plugins"`
}

// loadTrustState reads the record, reporting whether one existed. A store
// seen for the first time is recorded silently: there is nothing to compare
// against, and a warning listing every recipient of a fresh store would be
// noise the user learns to skip.
func loadTrustState(stateDir string) (trustState, bool) {
	var st trustState
	data, err := os.ReadFile(filepath.Join(stateDir, trustStateName)) //nolint:gosec // a path binpass owns.
	if err != nil {
		return st, false
	}
	if err := json.Unmarshal(data, &st); err != nil {
		// A corrupt record is treated as no record: re-learning the store
		// costs one missed warning, refusing to sync would cost the sync.
		return trustState{}, false
	}
	return st, true
}

// save writes the record with the same 0600/0700 discipline as the rest of
// the state directory.
func (t trustState) save(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, trustStateName), data, 0o600)
}

// scanRecipientFiles reads every recipients file in the store.
//
// A file that cannot be parsed is left out rather than recorded as empty: an
// unreadable .gpg-id is not the same statement as one listing nobody, and
// recording it as such would report a change on the next run.
func scanRecipientFiles(storeDir string) crypto.RecipientSets {
	out := crypto.RecipientSets{}
	_ = filepath.WalkDir(storeDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// .git holds every historical version of the recipients files;
			// only the checked-out ones decide what the next write targets.
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != crypto.GPGRecipientsFile && d.Name() != crypto.AgeRecipientsFile {
			return nil
		}
		rcp, rerr := crypto.ReadRecipientsFile(path)
		if rerr != nil {
			return nil
		}
		rel, rerr := filepath.Rel(storeDir, path)
		if rerr != nil {
			return nil
		}
		out[filepath.ToSlash(rel)] = crypto.RecipientStrings(rcp)
		return nil
	})
	return out
}

// reportStoreTrust compares the store's recipient sets and its own plugin
// directory against what the last sync recorded, and warns about anything
// that changed.
//
// It is a warning and never a prompt: a sync has to keep working from cron
// and from a hook, and a question nobody is there to answer would turn a
// security notice into a hang. It also never fails the sync — the change has
// already landed on disk by the time this runs, and refusing to report the
// rest of it helps nobody.
func (a *App) reportStoreTrust(storeDir string) {
	stateDir := a.syncStateDir()
	prev, seen := loadTrustState(stateDir)

	cur := trustState{
		Recipients: scanRecipientFiles(storeDir),
		Plugins:    plugin.SnapshotStorePlugins(storeDir),
	}
	if seen {
		a.warnRecipientChanges(crypto.DiffRecipientSets(prev.Recipients, cur.Recipients))
		a.warnStorePluginChanges(plugin.DiffStorePlugins(prev.Plugins, cur.Plugins))
	}
	if err := cur.save(stateDir); err != nil {
		fmt.Fprintf(a.Err, "warning: cannot record what the store trusts: %v\n", err)
	}
}

// warnRecipientChanges prints the recipient diff loudly enough to be noticed
// in a sync's normal output.
func (a *App) warnRecipientChanges(changes []crypto.RecipientChange) {
	for _, c := range changes {
		fmt.Fprintf(a.Err, "warning: the recipients in %s changed since the last sync\n", c.File)
		for _, r := range c.Added {
			if bin := crypto.AgePluginBinary(r); bin != "" {
				fmt.Fprintf(a.Err, "  + %s (age plugin recipient: encrypting runs %s)\n", r, bin)
				continue
			}
			fmt.Fprintf(a.Err, "  + %s\n", r)
		}
		for _, r := range c.Removed {
			fmt.Fprintf(a.Err, "  - %s\n", r)
		}
		fmt.Fprintf(a.Err, "  Everything written there from now on is encrypted to the keys listed above.\n"+
			"  If you did not change this, a remote did: check %s before the next insert or edit.\n", c.File)
	}
}

// warnStorePluginChanges reports plugins that arrived or changed inside the
// store.
//
// The store's plugin directory syncs with the store, and a plugin there
// provides a subcommand that dispatches before anything parses the command
// line — a typo is enough to run it. Noticing a new one required running
// `binpass plugin list` by hand, which nobody does after a routine sync.
func (a *App) warnStorePluginChanges(d plugin.StorePluginDiff) {
	if d.Empty() {
		return
	}
	fmt.Fprintln(a.Err, "warning: the plugins inside the store changed since the last sync")
	for _, name := range d.Added {
		fmt.Fprintf(a.Err, "  + %s (new)\n", name)
	}
	for _, name := range d.Changed {
		fmt.Fprintf(a.Err, "  ~ %s (manifest or executable replaced)\n", name)
	}
	for _, name := range d.Removed {
		fmt.Fprintf(a.Err, "  - %s (gone)\n", name)
	}
	fmt.Fprint(a.Err, "  `binpass <name>` now runs that program, as does any typo matching it.\n"+
		"  Review it with `binpass plugin list` before running anything.\n")
}
