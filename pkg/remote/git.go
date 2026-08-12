package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// GitRemote is a Remote backed by a git repository. It uses the system git
// binary via exec so that credential helpers, ssh-agent, commit signing, and
// proxies all work automatically. The commit messages match pass exactly so
// that the history is indistinguishable from a native pass repository (§8.3).
//
// For git, the store directory IS the git working tree. "Push" and "pull" are
// implicit: List/Get pull from the remote first, and Push flushes all local
// commits after applyActions.
type GitRemote struct {
	name    string
	dir     string
	url     string
	gitPath string
}

// GitOptions configures a GitRemote.
type GitOptions struct {
	// Name is the remote name, for example "origin".
	Name string
	// Dir is the password store directory (the git working tree).
	Dir string
	// URL is where that working tree pushes to. When set, the git remote is
	// created or corrected to point at it, so that `binpass remote add`
	// alone is enough to make sync work.
	URL string
	// GitPath overrides the git binary; empty means autodetect.
	GitPath string
}

// NewGitRemote returns a GitRemote. It initialises the store as a git working
// tree if it is not one already, and points the named git remote at URL.
//
// Both steps are done here because the alternative is asking the user to run
// `git init` and `git remote add` by hand after `binpass remote add` has
// apparently succeeded, and then watching sync silently do nothing.
func NewGitRemote(opts GitOptions) (*GitRemote, error) {
	gitPath := opts.GitPath
	if gitPath == "" {
		var err error
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("remote/git: git not found on PATH: %w", err)
		}
	}
	g := &GitRemote{name: opts.Name, dir: opts.Dir, url: opts.URL, gitPath: gitPath}
	ctx := context.Background()

	if _, err := g.git(ctx, "rev-parse", "--git-dir"); err != nil {
		if opts.URL == "" {
			return nil, fmt.Errorf("remote/git: %q is not a git working tree: %w", opts.Dir, err)
		}
		if _, err := g.git(ctx, "init", "-q"); err != nil {
			return nil, fmt.Errorf("remote/git: init %q: %w", opts.Dir, err)
		}
	}
	if opts.URL != "" {
		if err := g.ensureRemoteURL(ctx); err != nil {
			return nil, err
		}
	}
	if err := g.ensurePrivate(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// ensurePrivate restricts every store file in the working tree to its owner.
//
// Files arriving through checkout are created by git, which applies the
// user's umask: on a machine with the common 022 that leaves world-readable
// entries, handing the ciphertext of every synchronised password to any other
// account. core.sharedRepository does not help, since it governs the
// repository's own files rather than the checked-out tree, so the modes are
// set directly.
func (g *GitRemote) ensurePrivate(_ context.Context) error {
	return filepath.WalkDir(g.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Name() == ".git" && d.IsDir() {
			return filepath.SkipDir
		}
		want := os.FileMode(storeFilePerm)
		if d.IsDir() {
			want = storeDirPerm
		} else if !g.belongsInStore(path) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().Perm() == want {
			return nil
		}
		// The worktree is a private directory owned by this process; there is
		// no window for another user to swap a path for a symlink.
		return os.Chmod(path, want) //nolint:gosec // walk over our own private worktree.
	})
}

// ensureRemoteURL points the git remote at the configured URL, adding it when
// absent and correcting it when it disagrees.
//
// A stale URL is corrected rather than left alone: the binpass config is where
// the user just stated their intent, so it wins over whatever the repository
// was configured with earlier.
func (g *GitRemote) ensureRemoteURL(ctx context.Context) error {
	name := g.name
	if name == "" {
		name = "origin"
	}
	current, err := g.git(ctx, "remote", "get-url", name)
	if err != nil {
		if _, err := g.git(ctx, "remote", "add", name, g.url); err != nil {
			return fmt.Errorf("remote/git: remote add %s: %w", name, err)
		}
		return nil
	}
	if strings.TrimSpace(string(current)) == g.url {
		return nil
	}
	if _, err := g.git(ctx, "remote", "set-url", name, g.url); err != nil {
		return fmt.Errorf("remote/git: remote set-url %s: %w", name, err)
	}
	return nil
}

// Name returns the remote name.
func (g *GitRemote) Name() string { return g.name }

// Caps returns the git transport capabilities. Git provides atomic commits,
// full history, and rename support.
func (g *GitRemote) Caps() Caps {
	return Caps{
		Atomic:  true,
		History: true,
		Locking: false,
		Rename:  true,
		Watch:   false,
	}
}

// Pull fetches and rebases from the configured remote. This is called
// automatically before List and Get so the working tree reflects the
// latest remote state.
func (g *GitRemote) Pull(ctx context.Context) error {
	if !g.hasRemote(ctx) {
		return nil // nothing to pull from.
	}
	name := g.remoteName()

	// Whether this repository has any history of its own decides everything
	// below, and it must be answered before anything is committed.
	_, headErr := g.git(ctx, "rev-parse", "HEAD")
	fresh := headErr != nil

	if _, err := g.git(ctx, "fetch", name); err != nil {
		return fmt.Errorf("remote/git: fetch %s: %w", name, err)
	}
	branch, err := g.remoteHeadBranch(ctx, name)
	if err != nil {
		return err
	}

	// A store that has never been committed here, against a remote that
	// already holds one: adopt the remote's branch wholesale. This is the
	// state every second machine starts in, and reading its empty working
	// tree as "the remote's entries were deleted" would delete them.
	if fresh && branch != "" {
		if err := g.adoptRemoteBranch(ctx, name, branch); err != nil {
			return err
		}
		return nil
	}

	// Ordinary commands write to the store directly and know nothing about
	// git, so by the time sync runs the working tree usually holds edits the
	// repository has never seen. `git pull --rebase` refuses to run then,
	// and sync would fail for anyone who had merely used binpass between
	// syncs. Commit that work: it is the user's, and the merge engine needs
	// it recorded to compare against the remote.
	if err := g.commitLocalChanges(ctx); err != nil {
		return err
	}
	if branch == "" {
		return nil // the remote has no branch yet; the first push creates it.
	}

	// Rebase onto the remote branch by name. Relying on tracking information
	// fails on a branch that was created locally and never pushed, which is
	// what `git init` leaves behind.
	if _, err := g.git(ctx, "rebase", name+"/"+branch); err != nil {
		if strings.Contains(err.Error(), "Couldn't find remote ref") {
			return nil
		}
		// Both sides changed the same entry. Git cannot merge ciphertext,
		// so the rebase is abandoned and the remote becomes the working
		// tree — but only after every locally-changed entry is written
		// aside as a conflict file. Resetting first would destroy a
		// password the user had just set, which is the one outcome a
		// password manager may never produce.
		if _, abortErr := g.git(ctx, "rebase", "--abort"); abortErr != nil {
			return fmt.Errorf("remote/git: rebase onto %s/%s failed and could not be aborted: %w",
				name, branch, err)
		}
		if err := g.preserveDivergedFiles(ctx, name+"/"+branch); err != nil {
			return err
		}
		if _, err := g.git(ctx, "reset", "--hard", name+"/"+branch); err != nil {
			return fmt.Errorf("remote/git: adopt %s/%s after a diverged history: %w", name, branch, err)
		}
		return nil
	}
	return nil
}

// remoteName returns the git remote to use.
func (g *GitRemote) remoteName() string {
	if g.name == "" {
		return "origin"
	}
	return g.name
}

// remoteHeadBranch returns the branch a freshly fetched remote holds, so that
// a new clone checks out what the other machines are actually using rather
// than assuming a name like "main" or "master".
func (g *GitRemote) remoteHeadBranch(ctx context.Context, remoteName string) (string, error) {
	out, err := g.git(ctx, "for-each-ref", "--format=%(refname:strip=3)", "refs/remotes/"+remoteName)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		branch := strings.TrimSpace(line)
		if branch != "" && branch != "HEAD" {
			return branch, nil
		}
	}
	return "", nil
}

// Push flushes all local commits to the configured remote. This should be
// called after all Put/Delete/Rename operations are complete.
func (g *GitRemote) Push(ctx context.Context) error {
	if !g.hasRemote(ctx) {
		return nil // nothing to push to.
	}
	branch, err := g.currentBranch(ctx)
	if err != nil {
		return fmt.Errorf("remote/git: cannot determine the current branch: %w", err)
	}
	if _, err := g.git(ctx, "push", "origin", branch); err != nil {
		// If there's no upstream yet, set it.
		if strings.Contains(err.Error(), "no upstream") ||
			strings.Contains(err.Error(), "has no upstream") {
			if _, err := g.git(ctx, "push", "-u", "origin", branch); err != nil {
				return fmt.Errorf("remote/git: push -u: %w", err)
			}
			return nil
		}
		return fmt.Errorf("remote/git: push: %w", err)
	}
	return nil
}

// List returns all tracked files in the working tree that match the store
// extensions. It pulls from the remote first so the working tree reflects the
// latest remote state.
func (g *GitRemote) List(ctx context.Context) ([]File, error) {
	// Pull first so we see the latest remote state. A failure here must not
	// be swallowed: an empty listing is indistinguishable from "the remote
	// has nothing", which the merge engine reads as every remote entry
	// having been deleted.
	if err := g.Pull(ctx); err != nil {
		return nil, err
	}
	// Checkout created these files with git's umask, so tighten them before
	// anything is reported as present.
	if err := g.ensurePrivate(ctx); err != nil {
		return nil, err
	}

	out, err := g.git(ctx, "ls-files", "-z")
	if err != nil {
		return nil, fmt.Errorf("remote/git: list: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	// -z uses NUL as separator.
	paths := bytes.Split(out, []byte{0})
	var files []File
	for _, p := range paths {
		p = bytes.TrimSpace(p)
		if len(p) == 0 {
			continue
		}
		path := string(p)
		// Entries, and the tomb container when the store is closed. A
		// closed LUKS or sparse bundle store is only the container: listing
		// entries alone would report it as empty.
		if !IsStoreContent(path) || storeDotfiles[filepath.Base(path)] {
			continue
		}
		// A repository is under the control of whoever can push to it.
		if err := CheckPath(path); err != nil {
			return nil, err
		}
		rev, modTime, err := g.fileRev(ctx, path)
		if err != nil {
			rev = ""
			modTime = time.Time{}
		}
		size, _ := g.fileSize(ctx, path)
		files = append(files, File{
			Path:    path,
			Size:    size,
			ModTime: modTime,
			Rev:     rev,
		})
	}
	return files, nil
}

// Get returns the content of the file at path from the git working tree.
// It pulls from the remote first so the content is up to date.
func (g *GitRemote) Get(ctx context.Context, path string) (io.ReadCloser, string, error) {
	_ = g.Pull(ctx)

	out, err := g.git(ctx, "show", "HEAD:"+path)
	if err != nil {
		return nil, "", fmt.Errorf("remote/git: get %q: %w", path, err)
	}
	rev, err := g.headRev(ctx)
	if err != nil {
		return nil, "", err
	}
	return io.NopCloser(bytes.NewReader(out)), rev, nil
}

// Put stages the file and commits it. The commit message follows pass's exact
// format. The commit is local only; call Push after all operations to flush.
//
// expectRev is checked against the last commit that modified this file
// (not HEAD) to allow concurrent modifications to different files.
func (g *GitRemote) Put(ctx context.Context, path string, content io.Reader, expectRev string) (string, error) {
	absPath := filepath.Join(g.dir, path)

	// Conditional write: check the file's last-modifying commit matches.
	if expectRev != "" {
		fileRev, _, err := g.fileRev(ctx, path)
		if err != nil {
			return "", fmt.Errorf("remote/git: check rev for %q: %w", path, err)
		}
		if fileRev != expectRev {
			return "", fmt.Errorf("remote/git: conflict on %q: expected rev %q, got %q", path, expectRev, fileRev)
		}
	}

	// Write content to the working tree.
	data, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("remote/git: read content: %w", err)
	}
	if err := g.writeWorktree(absPath, data); err != nil {
		return "", err
	}

	// Stage and commit.
	relPath := path
	isNew, err := g.isNewFile(ctx, relPath)
	if err != nil {
		return "", err
	}

	msg := gitCommitMsg(relPath, isNew)
	if _, err := g.git(ctx, "add", relPath); err != nil {
		return "", fmt.Errorf("remote/git: add %q: %w", relPath, err)
	}
	// The content may already be committed: sync commits whatever ordinary
	// commands left in the working tree before pulling, and the file is then
	// written here with identical bytes. An empty commit is not a failure.
	if _, err := g.git(ctx, "diff", "--cached", "--quiet"); err != nil {
		if _, err := g.git(ctx, "commit", "-m", msg); err != nil {
			return "", fmt.Errorf("remote/git: commit: %w", err)
		}
	}

	rev, err := g.headRev(ctx)
	if err != nil {
		return "", err
	}
	return rev, nil
}

// Delete removes the file and commits the deletion. The commit is local only;
// call Push after all operations to flush.
func (g *GitRemote) Delete(ctx context.Context, path string, expectRev string) error {
	if expectRev != "" {
		fileRev, _, err := g.fileRev(ctx, path)
		if err != nil {
			return err
		}
		if fileRev != expectRev {
			return fmt.Errorf("remote/git: conflict on %q: expected rev %q, got %q", path, expectRev, fileRev)
		}
	}

	if _, err := g.git(ctx, "rm", "-f", path); err != nil {
		// A file that is already gone is the state this was asked to reach.
		// Failing here aborts the whole sync over an entry both sides have
		// agreed to remove, which is how one stale state entry could block
		// every future sync.
		if strings.Contains(err.Error(), "did not match any files") {
			return nil
		}
		return fmt.Errorf("remote/git: rm %q: %w", path, err)
	}
	msg := fmt.Sprintf("Remove %s from store.", stripExt(path))
	if _, err := g.git(ctx, "commit", "-m", msg); err != nil {
		return fmt.Errorf("remote/git: commit delete: %w", err)
	}
	return nil
}

// Rename moves a file in git (git mv) and commits. The commit is local only;
// call Push after all operations to flush.
func (g *GitRemote) Rename(ctx context.Context, from, to string) error {
	if _, err := g.git(ctx, "mv", from, to); err != nil {
		return fmt.Errorf("remote/git: mv %q -> %q: %w", from, to, err)
	}
	msg := fmt.Sprintf("Rename %s to %s.", stripExt(from), stripExt(to))
	if _, err := g.git(ctx, "commit", "-m", msg); err != nil {
		return fmt.Errorf("remote/git: commit rename: %w", err)
	}
	return nil
}

// Lock is a no-op for git. Git uses its own merge and locking model.
func (g *GitRemote) Lock(_ context.Context) (Unlock, error) {
	return NoopUnlock{}, nil
}

// Close is a no-op for git (no persistent connections).
func (g *GitRemote) Close() error { return nil }

// ---- helpers ----

// git runs a git command in the store directory and returns its stdout.
func (g *GitRemote) git(ctx context.Context, args ...string) ([]byte, error) {
	// The binary is resolved once from PATH and the arguments are built by
	// this package; entry paths reach git as operands after "--" or as
	// pathspecs, never as a command.
	cmd := exec.CommandContext(ctx, g.gitPath, args...) //nolint:gosec // fixed binary, arguments built internally.
	cmd.Dir = g.dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Several git commands, commit among them, explain a refusal on
			// stdout and leave stderr empty. Reporting only stderr produced
			// errors with no message at all.
			detail := strings.TrimSpace(string(exitErr.Stderr))
			if detail == "" {
				detail = strings.TrimSpace(string(out))
			}
			if detail == "" {
				detail = exitErr.String()
			}
			return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), detail)
		}
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// headRev returns the current HEAD commit SHA.
func (g *GitRemote) headRev(ctx context.Context) (string, error) {
	out, err := g.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// currentBranch returns the current branch name.
func (g *GitRemote) currentBranch(ctx context.Context) (string, error) {
	out, err := g.git(ctx, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// fileRev returns the last commit SHA that modified the given file and its
// commit timestamp.
func (g *GitRemote) fileRev(ctx context.Context, path string) (string, time.Time, error) {
	out, err := g.git(ctx, "log", "-1", "--format=%H %cI", "--", path)
	if err != nil {
		return "", time.Time{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), " ", 2)
	if len(parts) < 2 {
		return "", time.Time{}, fmt.Errorf("unexpected git log output for %q", path)
	}
	rev := parts[0]
	modTime, _ := time.Parse(time.RFC3339, parts[1])
	return rev, modTime, nil
}

// fileSize returns the file size from the git index.
func (g *GitRemote) fileSize(ctx context.Context, path string) (int64, error) {
	out, err := g.git(ctx, "cat-file", "-s", "HEAD:"+path)
	if err != nil {
		return 0, err
	}
	var size int64
	_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &size)
	return size, nil
}

// isNewFile reports whether the file has no previous commits.
func (g *GitRemote) isNewFile(ctx context.Context, path string) (bool, error) {
	out, err := g.git(ctx, "log", "--oneline", "-1", "--", path)
	if err != nil {
		return true, nil // assume new on error.
	}
	return len(strings.TrimSpace(string(out))) == 0, nil
}

// writeWorktree writes data to the file at absPath in the working tree,
// creating parent directories as needed. This must happen before `git add`
// stages the file.
func (g *GitRemote) writeWorktree(absPath string, data []byte) error {
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, storeDirPerm); err != nil {
		return fmt.Errorf("remote/git: mkdir %q: %w", dir, err)
	}
	// absPath was resolved against the worktree root by the caller.
	if err := os.WriteFile(absPath, data, storeFilePerm); err != nil { //nolint:gosec // path confined to the worktree.
		return fmt.Errorf("remote/git: write %q: %w", absPath, err)
	}
	return nil
}

// gitCommitMsg returns the commit message matching pass's format.
// New file:  "Add given password for <name> to store." (pass: cmd_insert)
// Edit:      "Edit password for <name> using binpass." (pass: cmd_edit uses $EDITOR).
func gitCommitMsg(path string, isNew bool) string {
	name := stripExt(path)
	if isNew {
		return fmt.Sprintf("Add given password for %s to store.", name)
	}
	return fmt.Sprintf("Edit password for %s using binpass.", name)
}

// stripExt removes the crypto extension from a store path, matching pass's
// display format: "github.com/alice.gpg" → "github.com/alice".
func stripExt(path string) string {
	ext := filepath.Ext(path)
	if ext != "" {
		return path[:len(path)-len(ext)]
	}
	return path
}

// hasRemote reports whether the repository has any git remote configured.
//
// `git remote` exits zero and prints nothing when there are none, so testing
// the exit status alone reported success and made Push and Pull silently do
// nothing: sync then announced it had finished without sending anything.
func (g *GitRemote) hasRemote(ctx context.Context) bool {
	out, err := g.git(ctx, "remote")
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// commitLocalChanges commits anything in the working tree that git does not
// yet know about, so that a rebase can proceed.
//
// Only store content is committed. Untracked files that belong to the store
// format (.gpg-id, .age-recipients, .gitattributes) are included because a
// clone without them cannot encrypt; anything else is left alone rather than
// swept into the user's history.
func (g *GitRemote) commitLocalChanges(ctx context.Context) error {
	// --untracked-files=all lists the files inside a new directory rather
	// than the directory alone. Without it a whole new subtree appears as a
	// single "?? mail/" entry, which does not look like store content and
	// so was skipped: every entry filed under a new folder went uncommitted
	// and never reached the remote.
	out, err := g.git(ctx, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return fmt.Errorf("remote/git: status: %w", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		return nil
	}

	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		// Renames are reported as "old -> new"; the new name is what exists.
		if i := strings.Index(path, " -> "); i >= 0 {
			path = path[i+4:]
		}
		path = strings.Trim(path, `"`)
		if path == "" || !g.belongsInStore(path) {
			continue
		}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil
	}

	args := append([]string{"add", "--"}, paths...)
	if _, err := g.git(ctx, args...); err != nil {
		return fmt.Errorf("remote/git: add local changes: %w", err)
	}
	// Nothing staged means the changes were all outside the store.
	if _, err := g.git(ctx, "diff", "--cached", "--quiet"); err == nil {
		return nil
	}
	if _, err := g.git(ctx, "commit", "-m", "Local changes made outside sync."); err != nil {
		return fmt.Errorf("remote/git: commit local changes: %w", err)
	}
	return nil
}

// belongsInStore reports whether a path is store content that sync owns.
func (g *GitRemote) belongsInStore(path string) bool {
	return IsStoreContent(path)
}

// adoptRemoteBranch points a store with no history of its own at the branch
// the remote already has.
//
// `binpass init` will usually have created a recipients file before the first
// sync, and a plain checkout refuses to overwrite untracked files. Those files
// are not lost work: they are local setup, and the remote's copy is the one
// the other machines agree on. The branch is reset onto them instead, which
// leaves any genuinely local entry in the working tree to be merged normally.
func (g *GitRemote) adoptRemoteBranch(ctx context.Context, remoteName, branch string) error {
	ref := remoteName + "/" + branch
	if _, err := g.git(ctx, "checkout", "-B", branch, "--track", ref); err == nil {
		return nil
	}
	// Move HEAD onto the remote branch without touching the working tree,
	// then take the remote's version of the files it tracks.
	if _, err := g.git(ctx, "checkout", "-B", branch); err != nil {
		return fmt.Errorf("remote/git: create branch %s: %w", branch, err)
	}
	if _, err := g.git(ctx, "reset", "--soft", ref); err != nil {
		return fmt.Errorf("remote/git: reset onto %s: %w", ref, err)
	}
	if _, err := g.git(ctx, "checkout", ref, "--", "."); err != nil {
		return fmt.Errorf("remote/git: take %s contents: %w", ref, err)
	}
	if _, err := g.git(ctx, "branch", "--set-upstream-to", ref, branch); err != nil {
		return fmt.Errorf("remote/git: track %s: %w", ref, err)
	}
	return nil
}

// preserveDivergedFiles copies every store entry that differs from the remote
// into a conflict file before the working tree is reset onto that remote.
//
// The naming matches what `binpass conflicts` expects, so the surviving copy
// is discoverable through the command built for it rather than being a stray
// file the user has to find.
func (g *GitRemote) preserveDivergedFiles(ctx context.Context, ref string) error {
	out, err := g.git(ctx, "diff", "--name-only", ref)
	if err != nil {
		return fmt.Errorf("remote/git: compare against %s: %w", ref, err)
	}
	stamp := time.Now().UTC().Format("20060102T150405")

	for _, line := range strings.Split(string(out), "\n") {
		path := strings.TrimSpace(line)
		if path == "" || !g.belongsInStore(path) {
			continue
		}
		// Recipients files are setup, not content worth keeping twice.
		if storeDotfiles[filepath.Base(path)] {
			continue
		}
		src := filepath.Join(g.dir, path)
		data, err := os.ReadFile(src) //nolint:gosec // a path inside the store.
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("remote/git: read %q: %w", path, err)
		}
		ext := filepath.Ext(path)
		dst := strings.TrimSuffix(path, ext) + ".conflict-" + g.deviceTag() + "-" + stamp + ext
		if err := g.writeWorktree(filepath.Join(g.dir, dst), data); err != nil {
			return err
		}
	}
	return nil
}

// deviceTag names this machine in a conflict file name.
func (g *GitRemote) deviceTag() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "local"
	}
	// Conflict names are parsed on dashes, so the host must not add more.
	return strings.ReplaceAll(host, "-", "_")
}
