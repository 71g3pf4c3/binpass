// Package vcs provides version-control integration for the password store.
// It isolates git operations behind an interface so that the caller (CLI
// history, TUI history view) does not depend on a particular git
// implementation. The current backend shells out to the system git binary;
// a future iteration will use go-git or the sync transport from feat/sync.
package vcs

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Commit is a single revision of a file in the password store.
type Commit struct {
	// Hash is the abbreviated commit SHA.
	Hash string
	// Author is the committer name and email.
	Author string
	// Date is the commit timestamp.
	Date time.Time
	// Subject is the first line of the commit message.
	Subject string
}

// LogOption controls how many commits are returned.
type LogOption struct {
	// Max limits the number of commits; zero means unlimited (up to git's
	// default, which is typically all commits for a single file).
	Max int
}

// Backend reads version-control information from a password store directory.
type Backend interface {
	// Log returns the commit history for the given entry path, newest first.
	// The path is relative to the store root and must not have a file
	// extension (it matches the name used by store.List).
	Log(entry string, opts LogOption) ([]Commit, error)
	// Show returns the content of an entry at a given commit hash.
	// The content is the raw bytes stored in the file, typically ciphertext.
	Show(entry, hash string) ([]byte, error)
	// Dir returns the store root directory.
	Dir() string
}

// GitBackend shells out to the system git binary. It requires the store
// directory to be a git repository.
type GitBackend struct {
	// dir is the password store root (PASSWORD_STORE_DIR).
	dir string
	// git is the path to the git binary; empty means "git" on PATH.
	git string
}

// NewGitBackend returns a Backend backed by the system git binary.
func NewGitBackend(storeDir string) *GitBackend {
	return &GitBackend{dir: storeDir}
}

// Dir returns the store root directory.
func (g *GitBackend) Dir() string { return g.dir }

// Log returns the commit history for entry, which is a store-relative path
// without file extension. It appends known extensions (.gpg, .age) so that
// git log can find the actual file.
func (g *GitBackend) Log(entry string, opts LogOption) ([]Commit, error) {
	// git log --format=... -- <glob>
	// We try both extensions; git log will silently ignore the one that
	// does not match any file.
	args := []string{
		"-C", g.dir,
		"log",
		"--format=%h%x00%an <%ae>%x00%ct%x00%s",
	}
	if opts.Max > 0 {
		args = append(args, fmt.Sprintf("-n%d", opts.Max))
	}
	args = append(args, "--")
	// Try both extensions.
	args = append(args, entry+".gpg", entry+".age")

	cmd := exec.Command(g.gitPath(), args...) //nolint:gosec // arguments are constructed internally.
	out, err := cmd.Output()
	if err != nil {
		// git log exits non-zero when the file is not tracked. This is not
		// a fatal error — it means the entry has no history.
		return nil, nil
	}
	return ParseLog(out)
}

// Show returns the file content at the given commit. This is ciphertext
// for encrypted entries; the caller must decrypt it.
func (g *GitBackend) Show(entry, hash string) ([]byte, error) {
	// Try both extensions.
	for _, ext := range []string{".gpg", ".age"} {
		args := []string{"-C", g.dir, "show", hash + ":" + entry + ext}
		cmd := exec.Command(g.gitPath(), args...) //nolint:gosec // arguments are constructed internally.
		out, err := cmd.Output()
		if err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("vcs: %s not found at %s", entry, hash)
}

// gitPath returns the git binary name.
func (g *GitBackend) gitPath() string {
	if g.git != "" {
		return g.git
	}
	return "git"
}

// ParseLog converts git log --format output into Commit slices.
// The format is: hash NUL author NUL timestamp NUL subject
// It is exported for use by CLI fallback paths.
func ParseLog(out []byte) ([]Commit, error) {
	if len(out) == 0 {
		return nil, nil
	}
	var commits []Commit
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "\x00", 4)
		if len(parts) < 4 {
			continue
		}
		ts, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			ts = 0
		}
		commits = append(commits, Commit{
			Hash:    parts[0],
			Author:  parts[1],
			Date:    time.Unix(ts, 0),
			Subject: parts[3],
		})
	}
	return commits, scanner.Err()
}

// NoopBackend is a Backend that always returns empty results. Used when the
// store is not a git repository.
type NoopBackend struct {
	dir string
}

// NewNoopBackend returns a Backend that reports no history.
func NewNoopBackend(storeDir string) *NoopBackend {
	return &NoopBackend{dir: storeDir}
}

func (n *NoopBackend) Log(string, LogOption) ([]Commit, error) { return nil, nil }
func (n *NoopBackend) Show(string, string) ([]byte, error) {
	return nil, fmt.Errorf("vcs: not a git repository")
}
func (n *NoopBackend) Dir() string { return n.dir }

// DetectBackend returns a GitBackend if the store directory contains a .git
// directory, or a NoopBackend otherwise.
func DetectBackend(storeDir string) Backend {
	if isGitRepo(storeDir) {
		return NewGitBackend(storeDir)
	}
	return NewNoopBackend(storeDir)
}

// isGitRepo reports whether dir contains a .git entry.
func isGitRepo(dir string) bool {
	// Quick check: .git can be a directory (standard) or a file (worktree).
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}
