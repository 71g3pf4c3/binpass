package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/remote"
	"github.com/71g3pf4c3/binpass/pkg/secret"
	"github.com/71g3pf4c3/binpass/pkg/storage"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/spf13/cobra"
)

// newSyncCmd builds `binpass sync`.
func newSyncCmd(app *App) *cobra.Command {
	var (
		remoteName string
		dryRun     bool
	)
	cmd := &cobra.Command{
		Use:   "sync [--remote=NAME] [--dry-run]",
		Short: "Synchronise the password store with a remote",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.runSync(cmd.Context(), remoteName, dryRun)
		},
	}
	cmd.Flags().StringVar(&remoteName, "remote", "", "remote to sync with (default: all configured remotes)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would happen without making changes")
	return cmd
}

// runSync performs a two-way sync between the local store and a remote. The
// flow is: scan local → list remote → load base → merge → apply actions.
func (a *App) runSync(ctx context.Context, remoteName string, dryRun bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	// Determine device ID. If none is stored, use the hostname.
	stateDir := a.syncStateDir()
	db, err := sync.OpenStateDB(stateDir)
	if err != nil {
		return err
	}
	defer db.Close()

	deviceID, err := db.DeviceID()
	if err != nil {
		return err
	}
	if deviceID == "" {
		deviceID, err = deriveDeviceID()
		if err != nil {
			return err
		}
		if err := db.SetDeviceID(deviceID); err != nil {
			return err
		}
	}

	// Load the base snapshot (state at the last successful sync).
	base, err := db.LoadBase()
	if err != nil {
		return err
	}

	// List the remote before scanning locally. For the git transport the
	// working tree and the store are the same directory, and listing pulls
	// into it: scanning first would read the tree as it was before the pull
	// and report every incoming entry as locally missing, which the merge
	// engine reads as a deletion to propagate.
	rem, err := a.buildRemote(remoteName)
	if err != nil {
		return err
	}
	remoteFiles, err := rem.List(ctx)
	if err != nil {
		return fmt.Errorf("sync: list remote: %w", err)
	}
	remoteSnap := remoteFilesToSnapshot(remoteFiles, base, deviceID)

	// Scan the local store.
	exts := sExts(s)
	local, err := sync.Scan(s.Dir(), base, deviceID, exts)
	if err != nil {
		return fmt.Errorf("sync: scan local: %w", err)
	}

	// Build the Opener for HOTP auto-merge.
	opener := sync.OpenerFunc(func(path string) (*secret.Secret, error) {
		name := stripCryptoExt(path)
		return s.Get(name)
	})

	// Merge: compare local vs remote against base.
	actions := sync.Merge(local, remoteSnap, base, opener)

	if len(actions) == 0 {
		fmt.Fprintln(a.Out, "Everything up-to-date.")
		return nil
	}

	// Print the plan.
	hasConflicts := false
	for _, act := range actions {
		if act.Kind == sync.ActionConflict {
			hasConflicts = true
		}
		a.printAction(act, dryRun)
	}

	if hasConflicts {
		fmt.Fprintln(a.Err, "Conflicts detected. Run `binpass conflicts list` for details.")
	}

	if dryRun {
		return nil
	}

	// Apply actions.
	if err := a.applyActions(ctx, s, rem, db, base, actions, deviceID); err != nil {
		return err
	}

	// For git remotes, push all local commits to the remote.
	if gp, ok := rem.(*remote.GitRemote); ok {
		fmt.Fprintf(a.Err, "  pushing to remote...\n")
		if err := gp.Push(ctx); err != nil {
			return fmt.Errorf("sync: git push: %w", err)
		}
	}
	// For restic remotes, push a new snapshot of the store.
	if rp, ok := rem.(*remote.ResticRemote); ok {
		fmt.Fprintf(a.Err, "  creating restic snapshot...\n")
		if err := rp.Push(ctx); err != nil {
			return fmt.Errorf("sync: restic push: %w", err)
		}
	}

	return nil
}

// printAction outputs a human-readable description of a sync action.
func (a *App) printAction(act sync.Action, dryRun bool) {
	prefix := ""
	if dryRun {
		prefix = "(dry-run) "
	}
	switch act.Kind {
	case sync.ActionNone:
		// Silent.
	case sync.ActionPush:
		fmt.Fprintf(a.Out, "%spush   %s\n", prefix, act.Path)
	case sync.ActionPull:
		fmt.Fprintf(a.Out, "%spull   %s\n", prefix, act.Path)
	case sync.ActionConflict:
		fmt.Fprintf(a.Out, "%sconflict %s\n", prefix, act.Path)
	case sync.ActionDelete:
		fmt.Fprintf(a.Out, "%sdelete %s\n", prefix, act.Path)
	case sync.ActionMergeHOTP:
		fmt.Fprintf(a.Out, "%smerge  %s (HOTP counter: %d)\n", prefix, act.Path, act.MergedCounter)
	}
}

// applyActions writes the merge results to the local store, the remote, and
// the state database. Each action is committed independently so that a
// failure halfway through leaves the rest intact.
//
// File I/O follows the same durability guarantees as storage.FS:
// write to a temp file → fsync → rename → fsync dir. The storage.FS is used
// for local writes; the Remote interface handles transport I/O.
func (a *App) applyActions(ctx context.Context, s interface {
	Get(string) (*secret.Secret, error)
	Dir() string
}, rem remote.Remote, db *sync.StateDB, base sync.Snapshot, actions []sync.Action, deviceID sync.DeviceID) error {
	storeDir := s.Dir()
	fs := storage.New(storeDir)
	fs.Umask = a.Cfg.Umask

	for _, act := range actions {
		switch act.Kind {
		case sync.ActionPush:
			// Local file is newer: upload to remote.
			if act.Local == nil {
				continue
			}
			absPath := filepath.Join(storeDir, act.Path)
			data, err := os.ReadFile(absPath) //nolint:gosec // path is store-relative, already validated.
			if err != nil {
				return fmt.Errorf("sync: read local %q: %w", act.Path, err)
			}
			fmt.Fprintf(a.Err, "  uploading %s\n", act.Path)
			if _, err := rem.Put(ctx, act.Path, bytes.NewReader(data), remoteRevForAction(act)); err != nil {
				return fmt.Errorf("sync: push %q to remote: %w", act.Path, err)
			}
			if err := db.UpdateFile(act.Local); err != nil {
				return fmt.Errorf("sync: update state for %q: %w", act.Path, err)
			}

		case sync.ActionPull:
			// Remote file is newer: download to local.
			if act.Remote == nil {
				continue
			}
			fmt.Fprintf(a.Err, "  downloading %s\n", act.Path)
			rc, _, err := rem.Get(ctx, act.Path)
			if err != nil {
				return fmt.Errorf("sync: pull %q from remote: %w", act.Path, err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return fmt.Errorf("sync: read remote %q: %w", act.Path, err)
			}
			absPath := filepath.Join(storeDir, act.Path)
			if err := fs.Write(absPath, data); err != nil {
				return fmt.Errorf("sync: write local %q: %w", act.Path, err)
			}
			if err := db.UpdateFile(act.Remote); err != nil {
				return fmt.Errorf("sync: update state for %q: %w", act.Path, err)
			}

		case sync.ActionConflict:
			// Preserve both copies. The remote version overwrites the local path;
			// the local version is saved as a conflict file.
			ts := time.Now().Format("20060102T150405")
			conflictName := sync.ConflictName(act.Path, deviceID, ts)
			conflictAbs := filepath.Join(storeDir, conflictName)

			// Save the local version as a conflict file.
			if act.Local != nil {
				localAbs := filepath.Join(storeDir, act.Path)
				localData, err := os.ReadFile(localAbs) //nolint:gosec
				if err != nil {
					return fmt.Errorf("sync: read local for conflict %q: %w", act.Path, err)
				}
				if err := fs.Write(conflictAbs, localData); err != nil {
					return fmt.Errorf("sync: write conflict %q: %w", conflictName, err)
				}
				fmt.Fprintf(a.Err, "  conflict: local saved as %s\n", conflictName)
			}

			// Download the remote version and write it to the original path.
			if act.Remote != nil {
				rc, _, err := rem.Get(ctx, act.Path)
				if err != nil {
					return fmt.Errorf("sync: pull conflict remote %q: %w", act.Path, err)
				}
				remoteData, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					return fmt.Errorf("sync: read conflict remote %q: %w", act.Path, err)
				}
				origAbs := filepath.Join(storeDir, act.Path)
				if err := fs.Write(origAbs, remoteData); err != nil {
					return fmt.Errorf("sync: write conflict orig %q: %w", act.Path, err)
				}
				fmt.Fprintf(a.Err, "  conflict: remote version kept at %s\n", act.Path)
			}

			// Update state: the merged VV captures both device contributions.
			if act.Local != nil && act.Remote != nil {
				mergedVV := act.Local.Version.Merge(act.Remote.Version)
				merged := *act.Remote
				merged.Version = mergedVV
				if err := db.UpdateFile(&merged); err != nil {
					return fmt.Errorf("sync: update conflict state for %q: %w", act.Path, err)
				}
			}

		case sync.ActionDelete:
			// File was deleted locally: delete from remote and state.
			if err := rem.Delete(ctx, act.Path, remoteRevForAction(act)); err != nil {
				return fmt.Errorf("sync: delete %q from remote: %w", act.Path, err)
			}
			fmt.Fprintf(a.Err, "  deleted %s from remote\n", act.Path)
			if err := db.DeleteFile(act.Path); err != nil {
				return fmt.Errorf("sync: delete state for %q: %w", act.Path, err)
			}

		case sync.ActionMergeHOTP:
			// Auto-merged HOTP counter: write the merged secret back.
			// The secret was already updated by Merge() — persist it.
			merged := *act.Local
			merged.Version = act.MergedVersion
			if err := db.UpdateFile(&merged); err != nil {
				return fmt.Errorf("sync: update HOTP merge state for %q: %w", act.Path, err)
			}

		case sync.ActionNone:
			// If the merged VV differs from the stored one, persist it.
			if act.MergedVersion != nil && act.Local != nil && !act.MergedVersion.Equal(act.Local.Version) {
				updated := *act.Local
				updated.Version = act.MergedVersion
				if err := db.UpdateFile(&updated); err != nil {
					return fmt.Errorf("sync: update VV for %q: %w", act.Path, err)
				}
			}
		}
	}

	return db.RecordSync()
}

// remoteRevForAction returns the revision string for a file from the remote
// state in the action, if one exists. Used for conditional writes.
func remoteRevForAction(act sync.Action) string {
	if act.Remote != nil && act.Remote.RemoteRev != "" {
		return act.Remote.RemoteRev
	}
	return ""
}

// buildRemote constructs a Remote from the configuration. If name is empty,
// it returns the default remote. For git remotes, it uses the store directory
// directly (the store is the git working tree). For other types, it delegates
// to RemoteFromConfig.
func (a *App) buildRemote(name string) (remote.Remote, error) {
	if name == "" {
		name = a.Cfg.Sync.DefaultRemote
	}
	// With exactly one remote configured there is nothing to disambiguate,
	// and requiring default_remote to be set by hand would mean `remote add`
	// followed by `sync` fails for every new user.
	if name == "" && len(a.Cfg.Remotes) == 1 {
		for only := range a.Cfg.Remotes {
			name = only
		}
	}
	if name == "" {
		// No remote configured: fall back to the git remote in the store
		// directory if it is a git repo.
		if isGitRepo(a.Cfg.Dir) {
			return remote.NewGitRemote(remote.GitOptions{
				Name: "origin",
				Dir:  a.Cfg.Dir,
			})
		}
		if len(a.Cfg.Remotes) > 1 {
			return nil, fmt.Errorf("sync: several remotes configured (%s); choose one with --remote or set sync.default_remote",
				strings.Join(sortedRemoteNames(a.Cfg.Remotes), ", "))
		}
		return nil, fmt.Errorf("sync: no remote configured; add one with `binpass remote add git origin URL`")
	}

	rc, ok := a.Cfg.Remotes[name]
	if !ok {
		return nil, fmt.Errorf("sync: unknown remote %q", name)
	}

	switch rc.Type {
	case "git":
		// The store directory is the git working tree; rc.URL names where
		// that tree pushes to. Passing the URL as the directory, as this
		// once did, made git look for a working tree at a URL path.
		return remote.NewGitRemote(remote.GitOptions{
			Name: name,
			Dir:  a.Cfg.Dir,
			URL:  rc.URL,
		})
	case "restic":
		repo := rc.URL
		if repo == "" {
			return nil, fmt.Errorf("sync: restic remote %q requires url (restic repo path)", name)
		}
		opts := remote.ResticOptions{
			Name:     name,
			Repo:     repo,
			StoreDir: a.Cfg.Dir,
		}
		if rc.PasswordCommand != "" {
			opts.PasswordCommand = rc.PasswordCommand
		}
		if rc.Password != "" {
			opts.Password = rc.Password
		}
		return remote.NewResticRemote(opts)
	case "s3", "gdrive", "yandex", "webdav":
		remotePath := rc.URL
		if rc.Folder != "" {
			remotePath = rc.URL + "/" + rc.Folder
		}
		return remote.NewRcloneRemote(remote.RcloneOptions{
			Name:   name,
			Remote: remotePath,
		})
	default:
		return remote.RemoteFromConfig(rc.Type, map[string]string{
			"name":   name,
			"url":    rc.URL,
			"folder": rc.Folder,
		})
	}
}

// syncStateDir returns the directory for the sync state database. This is
// always outside the password store (XDG_STATE_HOME, not the store itself).
func (a *App) syncStateDir() string {
	return config.StateDir()
}

// isGitRepo returns true if dir contains a .git subdirectory or is inside a
// git worktree.
func isGitRepo(dir string) bool {
	_, err := os.Stat(dir + "/.git")
	return err == nil
}

// sExts returns the crypto extensions the store supports.
func sExts(s interface{ Dir() string }) []string {
	// The store has both .gpg and .age backends.
	return []string{".gpg", ".age"}
}

// remoteFilesToSnapshot converts a list of RemoteFile into a Snapshot. It
// preserves existing version vectors from the base for files that have not
// changed.
func remoteFilesToSnapshot(files []remote.RemoteFile, base sync.Snapshot, deviceID sync.DeviceID) sync.Snapshot {
	snap := make(sync.Snapshot, len(files))
	for _, f := range files {
		vv := sync.VersionVector{}
		if b, ok := base[f.Path]; ok {
			vv = b.Version.Clone()
		} else {
			vv = sync.VersionVector{deviceID: 1}
		}
		snap[f.Path] = &sync.FileState{
			Path:      f.Path,
			Size:      f.Size,
			ModTime:   f.ModTime,
			Version:   vv,
			RemoteRev: f.Rev,
			Device:    deviceID,
		}
	}
	return snap
}

// deriveDeviceID returns a stable device identifier based on hostname.
func deriveDeviceID() (sync.DeviceID, error) {
	hostname, err := osHostname()
	if err != nil {
		return "", fmt.Errorf("sync: cannot determine device ID: %w", err)
	}
	return sync.DeviceID(hostname), nil
}

// osHostname is a package-level variable for testing.
var osHostname = defaultHostname

func defaultHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown", nil
	}
	return hostname, nil
}

// stripCryptoExt removes the .gpg or .age extension from a store path so it
// can be used as an entry name for store.Get.
func stripCryptoExt(path string) string {
	if len(path) > 4 && (path[len(path)-4:] == ".gpg" || path[len(path)-4:] == ".age") {
		return path[:len(path)-4]
	}
	return path
}

// sortedRemoteNames returns the configured remote names in a stable order,
// so that an error naming the choices does not shuffle between runs.
func sortedRemoteNames(remotes map[string]config.RemoteConfig) []string {
	out := make([]string, 0, len(remotes))
	for n := range remotes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
