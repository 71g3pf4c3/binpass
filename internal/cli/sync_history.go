package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/spf13/cobra"
)

// newSyncHistoryCmd builds `binpass sync history`: the list of points in time
// the configured remote can put the store back to. What a snapshot is depends
// on the transport — a restic snapshot, a git commit — so the command prints
// whatever the transport itself considers a revision, with enough identity
// for `sync restore` to name one.
func newSyncHistoryCmd(app *App) *cobra.Command {
	var remoteName string
	cmd := &cobra.Command{
		Use:   "history [--remote=NAME]",
		Short: "List the points in time the remote can restore the store to",
		Long: `List the restic snapshots or git commits a remote holds.

For a restic remote this is every snapshot binpass sync created; for a git
remote it is the commit history, newest first. The first column of a restic
listing is the ID ` + "`sync restore`" + ` accepts.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.runSyncHistory(cmd.Context(), remoteName)
		},
	}
	cmd.Flags().StringVar(&remoteName, "remote", "", "remote to list (default: the configured default remote)")
	return cmd
}

// newSyncRestoreCmd builds `binpass sync restore`: put the store back to a
// snapshot the remote holds.
func newSyncRestoreCmd(app *App) *cobra.Command {
	var remoteName string
	cmd := &cobra.Command{
		Use:   "restore SNAPSHOT-ID [--remote=NAME]",
		Short: "Restore the store from a snapshot on the remote",
		Long: `Restore the store's entries from a restic snapshot.

Entries changed since the snapshot are overwritten by their older versions;
entries created after the snapshot are left in place. The IDs are listed by
` + "`binpass sync history`" + `.

Only restic remotes can restore: a git remote's history is recovered with
git itself, which knows how to replay and merge it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.runSyncRestore(cmd.Context(), args[0], remoteName)
		},
	}
	cmd.Flags().StringVar(&remoteName, "remote", "", "remote to restore from (default: the configured default remote)")
	return cmd
}

// runSyncHistory prints the snapshot or commit list for the chosen remote.
func (a *App) runSyncHistory(ctx context.Context, remoteName string) error {
	// A device ID names this machine in the advisory lock; history only
	// reads, and passes the same value every other sync command does so
	// the remote is built identically.
	deviceID, err := a.currentDeviceID()
	if err != nil {
		return err
	}
	rem, err := a.buildRemote(remoteName, deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = rem.Close() }()

	switch r := rem.(type) {
	case *remote.ResticRemote:
		snaps, err := r.Snapshots(ctx)
		if err != nil {
			return fmt.Errorf("sync history: %w", err)
		}
		for _, s := range snaps {
			when := s.Time
			if t, err := time.Parse(time.RFC3339, s.Time); err == nil {
				when = t.Local().Format("2006-01-02 15:04:05")
			}
			line := fmt.Sprintf("%s  %s", s.ShortID, when)
			if s.Hostname != "" {
				line += "  " + s.Hostname
			}
			if len(s.Tags) > 0 {
				line += "  [" + strings.Join(s.Tags, ", ") + "]"
			}
			fmt.Fprintln(a.Out, line)
		}
		if len(snaps) == 0 {
			fmt.Fprintln(a.Out, "No snapshots yet; each `binpass sync` creates one.")
		}
		return nil

	case *remote.GitRemote:
		lines, err := r.Log(ctx, 0)
		if err != nil {
			return fmt.Errorf("sync history: %w", err)
		}
		for _, l := range lines {
			fmt.Fprintln(a.Out, l)
		}
		if len(lines) == 0 {
			fmt.Fprintln(a.Out, "No commits yet; each `binpass sync` makes one.")
		}
		return nil

	default:
		return fmt.Errorf("sync history: remote %s (%T) keeps no history; use a git or restic remote", rem.Name(), rem)
	}
}

// runSyncRestore restores the store from a restic snapshot.
func (a *App) runSyncRestore(ctx context.Context, snapshotID, remoteName string) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}
	deviceID, err := a.currentDeviceID()
	if err != nil {
		return err
	}
	rem, err := a.buildRemote(remoteName, deviceID)
	if err != nil {
		return err
	}
	defer func() { _ = rem.Close() }()

	restic, ok := rem.(*remote.ResticRemote)
	if !ok {
		return fmt.Errorf("sync restore: remote %s is a %T; only restic remotes restore", rem.Name(), rem)
	}

	// The snapshot is authoritative from here on; anything edited since it
	// was taken reverts. That is the point of the command, but it is also
	// the last moment it can be stopped, so it asks.
	ok, err = a.confirm("Restoring will overwrite entries changed since the snapshot. Continue?")
	if err != nil || !ok {
		return err
	}

	if err := restic.Restore(ctx, snapshotID, s.Dir()); err != nil {
		return fmt.Errorf("sync restore: %w", err)
	}
	fmt.Fprintf(a.Out, "Restored the store from snapshot %s.\n", snapshotID)
	fmt.Fprintln(a.Err, "The restored state is not recorded in the sync state; run `binpass sync` before editing entries to re-align it.")
	return nil
}

// currentDeviceID returns the device ID the sync engine records for this
// machine, deriving and storing one on first use. Reading the history does
// not need it, but every remote is built through the same path, and a remote
// built differently from the one that wrote the lock would be a surprise.
func (a *App) currentDeviceID() (sync.DeviceID, error) {
	db, err := sync.OpenStateDB(a.syncStateDir())
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	id, err := db.DeviceID()
	if err != nil {
		return "", err
	}
	if id != "" {
		return id, nil
	}
	id, err = deriveDeviceID()
	if err != nil {
		return "", err
	}
	if err := db.SetDeviceID(id); err != nil {
		return "", err
	}
	return id, nil
}
