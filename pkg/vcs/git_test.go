package vcs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestParseLogEmpty(t *testing.T) {
	commits, err := ParseLog(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 0 {
		t.Errorf("expected 0 commits, got %d", len(commits))
	}
}

func TestParseLogSingle(t *testing.T) {
	input := "a1b2c3d\x00Alice <alice@example.com>\x001728000000\x00Add given password for github/alice\n"
	commits, err := ParseLog([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	c := commits[0]
	if c.Hash != "a1b2c3d" {
		t.Errorf("Hash = %q, want %q", c.Hash, "a1b2c3d")
	}
	if c.Author != "Alice <alice@example.com>" {
		t.Errorf("Author = %q", c.Author)
	}
	if c.Subject != "Add given password for github/alice" {
		t.Errorf("Subject = %q", c.Subject)
	}
	wantTime := time.Unix(1728000000, 0)
	if !c.Date.Equal(wantTime) {
		t.Errorf("Date = %v, want %v", c.Date, wantTime)
	}
}

func TestParseLogMultiple(t *testing.T) {
	input := "abc1234\x00Bob <bob@x>\x001000000000\x00first\n" +
		"def5678\x00Bob <bob@x>\x001000000100\x00second\n"
	commits, err := ParseLog([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 2 {
		t.Fatalf("expected 2 commits, got %d", len(commits))
	}
	if commits[0].Hash != "abc1234" {
		t.Errorf("commits[0].Hash = %q", commits[0].Hash)
	}
	if commits[1].Hash != "def5678" {
		t.Errorf("commits[1].Hash = %q", commits[1].Hash)
	}
}

func TestParseLogMalformed(t *testing.T) {
	input := "not-enough-fields\n"
	commits, err := ParseLog([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 0 {
		t.Errorf("malformed line should be skipped, got %d commits", len(commits))
	}
}

func TestNoopBackend(t *testing.T) {
	b := NewNoopBackend("/tmp/test-store")
	commits, err := b.Log("entry", LogOption{})
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 0 {
		t.Errorf("noop backend should return 0 commits, got %d", len(commits))
	}
	_, err = b.Show("entry", "abc123")
	if err == nil {
		t.Error("noop backend Show should return an error")
	}
	if b.Dir() != "/tmp/test-store" {
		t.Errorf("Dir = %q, want %q", b.Dir(), "/tmp/test-store")
	}
}

// TestGitBackendIntegration creates a real git repo, commits a file, and
// verifies that Log and Show return correct results. Skipped if git is
// not available.
func TestGitBackendIntegration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Create a temp directory with a git repo.
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")

	// Create and commit an entry.
	entryPath := filepath.Join(dir, "entry.gpg")
	if err := os.WriteFile(entryPath, []byte("encrypted-content-v1"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "entry.gpg")
	runGit(t, dir, "commit", "-m", "Add given password for entry")

	backend := NewGitBackend(dir)

	// Test Log.
	commits, err := backend.Log("entry", LogOption{})
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("expected 1 commit, got %d", len(commits))
	}
	if commits[0].Subject != "Add given password for entry" {
		t.Errorf("Subject = %q", commits[0].Subject)
	}

	// Test Show.
	content, err := backend.Show("entry", commits[0].Hash)
	if err != nil {
		t.Fatalf("Show failed: %v", err)
	}
	if string(content) != "encrypted-content-v1" {
		t.Errorf("Show content = %q, want %q", string(content), "encrypted-content-v1")
	}

	// Test Log with Max.
	commitsLimited, err := backend.Log("entry", LogOption{Max: 1})
	if err != nil {
		t.Fatalf("Log with Max failed: %v", err)
	}
	if len(commitsLimited) != 1 {
		t.Errorf("Max=1 should return 1 commit, got %d", len(commitsLimited))
	}

	// Test Log for non-existent entry.
	commitsNone, err := backend.Log("nonexistent", LogOption{})
	if err != nil {
		t.Fatalf("Log for non-existent should not error: %v", err)
	}
	if len(commitsNone) != 0 {
		t.Errorf("non-existent entry should have 0 commits, got %d", len(commitsNone))
	}
}

func TestDetectBackend(t *testing.T) {
	// Non-git dir should return NoopBackend.
	tmpDir := t.TempDir()
	b := DetectBackend(tmpDir)
	if _, ok := b.(*NoopBackend); !ok {
		t.Error("non-git dir should return NoopBackend")
	}

	// Git dir should return GitBackend.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	runGit(t, tmpDir, "init")
	runGit(t, tmpDir, "config", "user.email", "test@test.com")
	runGit(t, tmpDir, "config", "user.name", "Test")
	b2 := DetectBackend(tmpDir)
	if _, ok := b2.(*GitBackend); !ok {
		t.Error("git dir should return GitBackend")
	}
}

func TestGitBackendDir(t *testing.T) {
	g := NewGitBackend("/some/dir")
	if g.Dir() != "/some/dir" {
		t.Errorf("Dir = %q, want %q", g.Dir(), "/some/dir")
	}
}

func TestGitBackendCustomGit(t *testing.T) {
	g := &GitBackend{dir: "/tmp", git: "/usr/bin/git"}
	if g.gitPath() != "/usr/bin/git" {
		t.Errorf("gitPath = %q, want %q", g.gitPath(), "/usr/bin/git")
	}
}

// runGit executes a git command in the given directory, failing the test on error.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=1970-01-01T00:00:00+0000", "GIT_COMMITTER_DATE=1970-01-01T00:00:00+0000")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %s: %v", args, string(out), err)
	}
}
