package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/71g3pf4c3/binpass/pkg/remote/fsremote"
	"github.com/71g3pf4c3/binpass/pkg/sync"
	"github.com/71g3pf4c3/binpass/pkg/syncadapter"
	"github.com/spf13/cobra"
)

// newSyncCmd builds the "sync" command.
func newSyncCmd() *cobra.Command {
	var fsPath string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronise the store with a remote",
		Long: "Synchronise the store with a directory-backed remote (shared " +
			"folder, USB drive, or cloud mount). Objects are pushed, the " +
			"manifest is committed under compare-and-swap, and remote changes " +
			"are pulled. Conflicts are never lost — the local side is kept as a " +
			"sibling copy.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := stateOf(cmd).cfg
			path := fsPath
			if path == "" {
				path = cfg.Sync.FSPath
			}
			if path == "" {
				return fmt.Errorf("sync: no remote configured (set sync.fs_path or --path)")
			}

			st, err := openStore(cmd)
			if err != nil {
				return err
			}
			deviceID, err := deviceID()
			if err != nil {
				return err
			}
			adapter, err := syncadapter.New(st, deviceID)
			if err != nil {
				return err
			}
			rem, err := fsremote.New(path)
			if err != nil {
				return err
			}
			defer rem.Close()

			engine := sync.NewEngine(adapter, adapter)
			report, err := engine.Sync(cmd.Context(), rem)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "synced with %s: pushed %d, pulled %d, generation %d\n",
				rem.Name(), report.Pushed, report.Pulled, report.Generation)
			if len(report.Conflicts) > 0 {
				fmt.Fprintf(out, "%d conflict(s):\n", len(report.Conflicts))
				for _, c := range report.Conflicts {
					fmt.Fprintf(out, "  %s (%s) — local copy kept as sibling\n", c.Path, c.Kind)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fsPath, "path", "", "directory-backed remote path")
	return cmd
}

// deviceID returns a stable per-machine device identifier, creating it under
// the config directory on first use.
func deviceID() (string, error) {
	dir := config.ConfigDir()
	path := filepath.Join(dir, "device_id")
	if data, err := os.ReadFile(path); err == nil {
		return string(trimNewline(data)), nil
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sync: device id: %w", err)
	}
	id := "dev-" + hex.EncodeToString(b)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("sync: write device id: %w", err)
	}
	return id, nil
}

// trimNewline strips a single trailing newline from b.
func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
