package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	gitPath string
}

// GitOptions configures a GitRemote.
type GitOptions struct {
	// Name is the remote name, for example "origin".
	Name string
	// Dir is the password store directory (the git working tree).
	Dir string
	// GitPath overrides the git binary; empty means autodetect.
	GitPath string
}

// NewGitRemote returns a GitRemote. It validates that git is available on the
// system and that Dir is a git working tree.
func NewGitRemote(opts GitOptions) (*GitRemote, error) {
	gitPath := opts.GitPath
	if gitPath == "" {
		var err error
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("remote/git: git not found on PATH: %w", err)
		}
	}
	g := &GitRemote{name: opts.Name, dir: opts.Dir, gitPath: gitPath}
	if _, err := g.git(context.Background(), "rev-parse", "--git-dir"); err != nil {
		return nil, fmt.Errorf("remote/git: %q is not a git working tree: %w", opts.Dir, err)
	}
	return g, nil
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
	// Check if a remote is configured.
	if _, err := g.git(ctx, "remote"); err != nil {
		return nil // no remote configured, skip pull.
	}
	// git pull --rebase avoids merge commits.
	if _, err := g.git(ctx, "pull", "--rebase"); err != nil {
		// If the repo is empty or has no upstream, pull fails — that's OK.
		if strings.Contains(err.Error(), "no remote") ||
			strings.Contains(err.Error(), "no upstream") ||
			strings.Contains(err.Error(), "Couldn't find remote ref") {
			return nil
		}
		return fmt.Errorf("remote/git: pull: %w", err)
	}
	return nil
}

// Push flushes all local commits to the configured remote. This should be
// called after all Put/Delete/Rename operations are complete.
func (g *GitRemote) Push(ctx context.Context) error {
	if _, err := g.git(ctx, "remote"); err != nil {
		return nil // no remote configured, skip push.
	}
	branch, err := g.currentBranch(ctx)
	if err != nil {
		return nil
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
func (g *GitRemote) List(ctx context.Context) ([]RemoteFile, error) {
	// Pull first so we see the latest remote state.
	_ = g.Pull(ctx)

	out, err := g.git(ctx, "ls-files", "-z")
	if err != nil {
		return nil, fmt.Errorf("remote/git: list: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	// -z uses NUL as separator.
	paths := bytes.Split(out, []byte{0})
	var files []RemoteFile
	for _, p := range paths {
		p = bytes.TrimSpace(p)
		if len(p) == 0 {
			continue
		}
		path := string(p)
		// Skip dotfiles: .gitattributes, .gpg-id, .age-recipients, etc.
		if len(path) > 0 && path[0] == '.' {
			continue
		}
		// Skip non-crypto files (no .gpg or .age extension).
		ext := filepath.Ext(path)
		if ext != ".gpg" && ext != ".age" {
			continue
		}
		rev, modTime, err := g.fileRev(ctx, path)
		if err != nil {
			rev = ""
			modTime = time.Time{}
		}
		size, _ := g.fileSize(ctx, path)
		files = append(files, RemoteFile{
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
	if _, err := g.git(ctx, "commit", "-m", msg); err != nil {
		return "", fmt.Errorf("remote/git: commit: %w", err)
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
	cmd := exec.CommandContext(ctx, g.gitPath, args...)
	cmd.Dir = g.dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), string(exitErr.Stderr))
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
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &size)
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("remote/git: mkdir %q: %w", dir, err)
	}
	if err := os.WriteFile(absPath, data, 0o644); err != nil {
		return fmt.Errorf("remote/git: write %q: %w", absPath, err)
	}
	return nil
}

// gitCommitMsg returns the commit message matching pass's format.
// New file:  "Add given password for <name> to store." (pass: cmd_insert)
// Edit:      "Edit password for <name> using binpass." (pass: cmd_edit uses $EDITOR)
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
