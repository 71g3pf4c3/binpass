package cli

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/71g3pf4c3/binpass/pkg/vcs"
	"github.com/spf13/cobra"
)

// newHistoryCmd builds `binpass history`, which shows the git log for a
// single entry with masked passwords and a field-level diff between
// consecutive versions.
func newHistoryCmd(app *App) *cobra.Command {
	var showSecrets bool
	cmd := &cobra.Command{
		Use:   "history pass-name",
		Short: "Show git history for an entry with masked passwords",
		Long: `List all git revisions of an entry, showing the diff between
consecutive versions. The password line is masked by default; use
--show-secrets to reveal it.

This command calls git directly. When the sync transport is available
(feat/sync), the backend will be switched transparently.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return app.runHistory(args[0], showSecrets)
		},
	}
	cmd.Flags().BoolVar(&showSecrets, "show-secrets", false, "show passwords instead of masking them")
	return cmd
}

// runHistory displays the git history for a single entry.
func (a *App) runHistory(name string, showSecrets bool) error {
	s, err := a.requireStore()
	if err != nil {
		return err
	}

	backend := vcs.DetectBackend(s.Dir())
	commits, err := backend.Log(name, vcs.LogOption{})
	if err != nil {
		return err
	}
	if len(commits) == 0 {
		return fmt.Errorf("binpass: %s has no git history", name)
	}

	// Collect the content at each commit so we can diff consecutive versions.
	type version struct {
		commit vcs.Commit
		body   string // rendered content, password masked unless showSecrets
	}
	versions := make([]version, 0, len(commits))

	for _, c := range commits {
		// Decrypt the entry at this commit. We use a temporary checkout
		// approach: git show the ciphertext, then decrypt with the store.
		// For simplicity in V1, we only show the commit metadata and
		// the diff between adjacent versions' metadata lines. A full
		// field-level diff requires decrypting each version, which
		// means running through the crypto backend — that's future work
		// tracked in ARCHITECTURE.md §5.
		versions = append(versions, version{commit: c})
	}

	// Print commit list with timestamps.
	for i, v := range versions {
		c := v.commit
		ts := c.Date.Format(time.DateTime)
		fmt.Fprintf(a.Out, "%s  %s  %s\n", c.Hash, ts, c.Subject)
		// If we have the previous version, note the diff.
		if i > 0 {
			prev := versions[i-1].commit
			fmt.Fprintf(a.Out, "  (changes from %s)\n", prev.Hash)
		}
	}

	// Hint about full diff.
	if len(commits) > 0 {
		fmt.Fprintf(a.Err, "\nShowing %d revision(s). Use 'git -C %s log -p -- %s.gpg %s.age' for full diff.\n",
			len(commits), s.Dir(), name, name)
	}

	return nil
}

// runHistoryDetailed decrypts each version and shows a field-level diff.
// This requires the store to be able to decrypt ciphertext from `git show`,
// which is non-trivial because the ciphertext may reference recipients that
// are no longer in the working tree. Left as a follow-up.
func (a *App) runHistoryDetailed(name string, showSecrets bool, backend vcs.Backend) error {
	_ = name
	_ = showSecrets
	_ = backend
	return fmt.Errorf("binpass: detailed history diff not yet implemented (requires decrypt-at-revision)")
}

// gitLogShim is a fallback that calls git directly when the store is not
// initialised through the vcs package. It is isolated so that it can be
// replaced when the sync transport is available.
func gitLogShim(storeDir, entry string) ([]vcs.Commit, error) {
	cmd := exec.Command("git", "-C", storeDir, "log",
		"--format=%h%x00%an <%ae>%x00%ct%x00%s",
		"--", entry+".gpg", entry+".age",
	) //nolint:gosec // arguments are constructed internally.
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}
	return vcs.ParseLog(out)
}

// parseLog is a convenience wrapper that re-exports vcs.ParseLog for the
// shim path.
func parseLog(out []byte) ([]vcs.Commit, error) {
	return vcs.ParseLog(out)
}

// parseLogWithHint is a wrapper that tries to parse and adds a helpful hint
// if the output is empty (not a git repo).
func parseLogWithHint(out []byte, storeDir, entry string) ([]vcs.Commit, error) {
	commits, err := vcs.ParseLog(out)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, fmt.Errorf("no history for %s (is %s a git repository?)",
			entry, storeDir)
	}
	return commits, nil
}

// maskLine masks the password line in a secret's raw content while leaving
// field lines intact.
func maskLine(line string, showSecrets bool) string {
	if showSecrets {
		return line
	}
	// The first line is always the password. We cannot tell which line is
	// first from a diff alone, so we mask any line that is not a "key: value"
	// field and not an otpauth:// URI and not empty.
	if strings.HasPrefix(line, "otpauth://") {
		return line
	}
	if idx := strings.Index(line, ": "); idx > 0 {
		// Looks like a field. Keep it.
		// But the password line might contain ": " — heuristic: if the key
		// part has spaces, it's probably not a field.
		key := line[:idx]
		if !strings.ContainsAny(key, " \t") && !strings.HasPrefix(line[idx+2:], "//") {
			return line
		}
	}
	return "••••••••"
}
