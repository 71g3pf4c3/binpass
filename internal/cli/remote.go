package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// newRemoteCmd builds `binpass remote`.
func newRemoteCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage synchronisation remotes",
	}

	cmd.AddCommand(
		newRemoteAddCmd(app),
		newRemoteRemoveCmd(app),
		newRemoteListCmd(app),
	)
	return cmd
}

// newRemoteAddCmd builds `binpass remote add`.
func newRemoteAddCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "add TYPE NAME [URL]",
		Short: "Add a synchronisation remote",
		Long: `Add a new remote for synchronisation. TYPE is one of:
  git       — a git repository (the default pass transport)
  restic    — a restic repository (encrypted, deduplicated, versioned snapshots)
  gdrive    — Google Drive folder
  yandex    — Yandex.Disk folder
  webdav    — WebDAV endpoint
  s3        — S3-compatible bucket

For git, the URL is required.

For restic, the URL is the repository, passed to restic untouched, so every
backend it supports works:

  /mnt/backup/binpass                     a local or mounted disk
  sftp:user@host:/srv/binpass             SFTP
  s3:s3.amazonaws.com/bucket/binpass      S3, MinIO, Garage, Wasabi
  b2:bucket:binpass                       Backblaze B2
  azure:container:/binpass                Azure Blob Storage
  gs:bucket:/binpass                      Google Cloud Storage
  swift:container:/binpass                OpenStack Swift
  rest:https://host:8000/binpass          a rest-server
  rclone:remote:binpass                   anything rclone speaks

That last one reaches Google Drive, Dropbox and OneDrive with restic's
deduplication and snapshots on top, which suits a store with a tomb far
better than storing plain files does.

For cloud remotes, binpass will guide you through OAuth on first use.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runRemoteAdd(args[0], args[1], args[2:]...)
		},
	}
}

// newRemoteRemoveCmd builds `binpass remote remove`.
func newRemoteRemoveCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:     "remove NAME",
		Aliases: []string{"rm"},
		Short:   "Remove a synchronisation remote",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runRemoteRemove(args[0])
		},
	}
}

// newRemoteListCmd builds `binpass remote list`.
func newRemoteListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured remotes",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.runRemoteList()
		},
	}
}

// runRemoteAdd persists a remote to the config file under sync.remotes.<name>.
func (a *App) runRemoteAdd(remoteType, name string, extra ...string) error {
	validTypes := map[string]bool{
		"git": true, "restic": true, "gdrive": true, "yandex": true, "webdav": true, "s3": true,
	}
	if !validTypes[remoteType] {
		return fmt.Errorf("remote add: unknown type %q (valid: git, restic, gdrive, yandex, webdav, s3)", remoteType)
	}

	rc := config.RemoteConfig{
		Type: remoteType,
	}
	if len(extra) > 0 {
		rc.URL = extra[0]
	}
	if len(extra) > 1 {
		rc.Folder = extra[1]
	}

	cfgPath := config.FilePath()
	if err := upsertRemoteYAML(cfgPath, name, rc); err != nil {
		return fmt.Errorf("remote add: %w", err)
	}

	// Update in-memory config.
	if a.Cfg.Remotes == nil {
		a.Cfg.Remotes = make(map[string]config.RemoteConfig)
	}
	a.Cfg.Remotes[name] = rc

	fmt.Fprintf(a.Out, "Added remote %q (type=%s).\n", name, remoteType)
	return nil
}

// runRemoteRemove removes a remote from the config file.
func (a *App) runRemoteRemove(name string) error {
	if _, ok := a.Cfg.Remotes[name]; !ok {
		return fmt.Errorf("remote remove: %q not found", name)
	}

	cfgPath := config.FilePath()
	if err := deleteRemoteYAML(cfgPath, name); err != nil {
		return fmt.Errorf("remote remove: %w", err)
	}

	delete(a.Cfg.Remotes, name)
	fmt.Fprintf(a.Out, "Removed remote %q.\n", name)
	return nil
}

// runRemoteList prints the configured remotes in a table.
func (a *App) runRemoteList() error {
	if len(a.Cfg.Remotes) == 0 {
		fmt.Fprintln(a.Out, "No remotes configured.")
		return nil
	}

	tw := tabwriter.NewWriter(a.Out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tURL\tFOLDER")

	// Deterministic output order.
	names := make([]string, 0, len(a.Cfg.Remotes))
	for n := range a.Cfg.Remotes {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		rc := a.Cfg.Remotes[name]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, rc.Type, rc.URL, rc.Folder)
	}
	return tw.Flush()
}

// upsertRemoteYAML reads the config file, inserts or updates the named remote,
// and writes it back. Creates the file if it does not exist.
func upsertRemoteYAML(path, name string, rc config.RemoteConfig) error {
	root := make(map[string]interface{})
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is the resolved binpass config file.
		_ = yaml.Unmarshal(data, &root)
	}

	// Navigate to sync.remotes.<name>, creating intermediate maps.
	syncMap, _ := root["sync"].(map[string]interface{})
	if syncMap == nil {
		syncMap = make(map[string]interface{})
	}
	remotesMap, _ := syncMap["remotes"].(map[string]interface{})
	if remotesMap == nil {
		remotesMap = make(map[string]interface{})
	}

	entry := map[string]interface{}{
		"type": rc.Type,
	}
	if rc.URL != "" {
		entry["url"] = rc.URL
	}
	if rc.Folder != "" {
		entry["folder"] = rc.Folder
	}
	if rc.SignCommits {
		entry["sign_commits"] = true
	}
	if rc.Password != "" {
		entry["password"] = rc.Password
	}
	if rc.PasswordCommand != "" {
		entry["password_command"] = rc.PasswordCommand
	}

	remotesMap[name] = entry
	syncMap["remotes"] = remotesMap
	root["sync"] = syncMap

	return writeYAML(path, root)
}

// deleteRemoteYAML reads the config file, removes the named remote,
// and writes it back.
func deleteRemoteYAML(path, name string) error {
	root := make(map[string]interface{})
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is the resolved binpass config file.
		_ = yaml.Unmarshal(data, &root)
	}

	syncMap, _ := root["sync"].(map[string]interface{})
	if syncMap == nil {
		return nil
	}
	remotesMap, _ := syncMap["remotes"].(map[string]interface{})
	if remotesMap == nil {
		return nil
	}

	delete(remotesMap, name)
	if len(remotesMap) == 0 {
		delete(syncMap, "remotes")
	}
	if len(syncMap) == 0 {
		delete(root, "sync")
	}

	return writeYAML(path, root)
}

// writeYAML marshals root to YAML and writes it atomically.
func writeYAML(path string, root map[string]interface{}) error {
	data, err := yaml.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// The config directory does not exist until something writes to it, and
	// `remote add` is usually the first command that does. Without this the
	// very first remote fails on a machine that has no config yet.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	// Write to a temp file in the same directory, then rename.
	tmp, err := os.CreateTemp(dir, ".binpass-config-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	// The config names every remote and may carry credentials in a URL, so
	// it is not world-readable. CreateTemp makes 0600 files, but the mode is
	// set explicitly rather than inherited from an implementation detail.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	// The rename below is not atomic with respect to a crash unless the data
	// has reached the disk first.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
