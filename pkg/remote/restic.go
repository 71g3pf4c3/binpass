package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ResticRemote is a Remote backed by a restic repository. It delegates all I/O
// to the system restic binary so that the user's restic configuration (password
// command, S3 credentials, SFTP keys, etc.) is used automatically.
//
// The model is similar to GitRemote: the password store directory IS the backup
// source. Mutations (Put, Delete, Rename) modify the local store; Push creates a
// new restic snapshot that captures the current state. List and Get read from the
// latest snapshot via "restic ls" and "restic dump".
//
// Revision tracking uses the restic snapshot short ID (8 hex characters). Before
// Push, the engine checks that the latest snapshot ID matches the one observed
// during List; if it differs, another client has pushed and the operation is a
// conflict.
type ResticRemote struct {
	name        string
	repo        string   // -r value: "s3:bucket/path", "/local/repo", "sftp:user:host", etc.
	passwordCmd string   // --password-command (preferred over RESTIC_PASSWORD)
	password    string   // RESTIC_PASSWORD env (fallback)
	storeDir    string   // password store directory (the backup source)
	resticPath  string   // path to restic binary
	extraArgs   []string // additional CLI args (e.g. --option s3.region=eu-west-1)
	extraEnv    []string // extra env vars (AWS_ACCESS_KEY_ID, etc.)

	mu         chan struct{} // serialises Push to avoid double-snapshot races
	lastSnapID string        // snapshot ID from last List call (for conditional write)
	dirty      bool          // true if Put/Delete/Rename modified the local store
	initDone   bool          // true after repo is verified or initialised
}

// ResticOptions configures a ResticRemote.
type ResticOptions struct {
	// Name is the human-readable remote name, e.g. "backup-s3".
	Name string
	// Repo is the restic repository, e.g. "s3:s3.amazonaws.com/bucket/path"
	// or "/mnt/backup" or "sftp:user@server:/backup".
	Repo string
	// Password is the repository password. Prefer PasswordCommand for
	// production use; this field is for testing.
	Password string
	// PasswordCommand is a shell command that prints the password to stdout,
	// passed as --password-command to restic.
	PasswordCommand string
	// StoreDir is the local password store directory (the backup source).
	StoreDir string
	// ResticPath overrides the restic binary; empty means autodetect.
	ResticPath string
	// ExtraArgs are additional flags passed to every restic invocation.
	ExtraArgs []string
	// ExtraEnv are extra environment variables for the restic process.
	ExtraEnv []string
}

// NewResticRemote creates a ResticRemote. It validates that the restic binary is
// available and that StoreDir exists.
func NewResticRemote(opts ResticOptions) (*ResticRemote, error) {
	resticPath := opts.ResticPath
	if resticPath == "" {
		var err error
		resticPath, err = exec.LookPath("restic")
		if err != nil {
			return nil, fmt.Errorf("remote/restic: restic not found on PATH: %w", err)
		}
	}
	if opts.Repo == "" {
		return nil, fmt.Errorf("remote/restic: repo is required")
	}
	if opts.StoreDir == "" {
		return nil, fmt.Errorf("remote/restic: store directory is required")
	}
	if _, err := os.Stat(opts.StoreDir); err != nil {
		return nil, fmt.Errorf("remote/restic: store directory %q: %w", opts.StoreDir, err)
	}
	r := &ResticRemote{
		name:        opts.Name,
		repo:        opts.Repo,
		password:    opts.Password,
		passwordCmd: opts.PasswordCommand,
		storeDir:    opts.StoreDir,
		resticPath:  resticPath,
		extraArgs:   opts.ExtraArgs,
		extraEnv:    opts.ExtraEnv,
		mu:          make(chan struct{}, 1),
	}
	r.mu <- struct{}{} // initialise as unlocked
	return r, nil
}

// Name returns the remote name.
func (r *ResticRemote) Name() string { return r.name }

// Caps returns restic transport capabilities. Restic provides full history
// (snapshots), weak atomicity (append-only, verify via snapshot ID), and local
// rename support. It does not support atomic single-file Put or watch.
func (r *ResticRemote) Caps() Caps {
	return Caps{
		Atomic:     false,
		WeakAtomic: true,
		History:    true,
		Locking:    false,
		Rename:     true,
		Watch:      false,
	}
}

// Pull is a no-op for restic. The latest snapshot is read on demand by List and
// Get, so there is no separate fetch step.
func (r *ResticRemote) Pull(_ context.Context) error { return nil }

// Push creates a new restic snapshot if the local store has been modified. It
// checks that the latest snapshot ID matches the one observed during List; if
// another client has pushed in the meantime, it returns an error.
func (r *ResticRemote) Push(ctx context.Context) error {
	<-r.mu
	defer func() { r.mu <- struct{}{} }()

	if !r.dirty {
		return nil
	}

	// Conditional write: check that the latest snapshot hasn't changed.
	if r.lastSnapID != "" {
		latest, err := r.latestSnapshotID(ctx)
		if err == nil && latest != r.lastSnapID {
			return fmt.Errorf("remote/restic: snapshot %q pushed by another client (expected %q): pull and re-merge first",
				latest, r.lastSnapID)
		}
	}

	// Ensure the repo is initialised.
	if err := r.ensureInit(ctx); err != nil {
		return err
	}

	// Run restic backup.
	args := r.buildArgs("backup", r.storeDir)
	args = append(args, "--tag", "binpass")
	out, err := r.run(ctx, args)
	if err != nil {
		return fmt.Errorf("remote/restic: backup: %w", err)
	}

	// Update the last known snapshot ID from the backup output.
	newID := parseSnapshotID(string(out))
	if newID != "" {
		r.lastSnapID = newID
	}
	r.dirty = false
	return nil
}

// List returns all .gpg and .age files in the latest snapshot. It queries the
// restic repository via "restic ls latest --json" and records the snapshot ID as
// the revision for conditional writes.
func (r *ResticRemote) List(ctx context.Context) ([]File, error) {
	if err := r.ensureInit(ctx); err != nil {
		return nil, err
	}

	// Get the latest snapshot ID first.
	snapID, err := r.latestSnapshotID(ctx)
	if err != nil {
		return nil, fmt.Errorf("remote/restic: list: %w", err)
	}

	// restic ls <snapshot> --json
	args := r.buildArgs("ls", snapID, "--json")
	out, err := r.run(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("remote/restic: ls: %w", err)
	}

	var files []File
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry resticLsEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip unparseable lines (snapshot header, etc.)
		}
		if entry.Type != "file" {
			continue
		}
		path := r.toStoreRelative(entry.Path)
		if path == "" {
			continue
		}
		// Skip dotfiles.
		if isDotfile(path) {
			continue
		}
		// Only crypto files.
		ext := filepath.Ext(path)
		if ext != ".gpg" && ext != ".age" {
			continue
		}
		var modTime time.Time
		if entry.Mtime != "" {
			modTime, _ = time.Parse(time.RFC3339, entry.Mtime)
		}
		files = append(files, File{
			Path:    path,
			Size:    entry.Size,
			ModTime: modTime,
			Rev:     snapID,
		})
	}

	r.lastSnapID = snapID
	return files, nil
}

// Get downloads a single file from the latest snapshot via "restic dump". It
// returns the file content, the snapshot ID as the revision, and any error.
func (r *ResticRemote) Get(ctx context.Context, path string) (io.ReadCloser, string, error) {
	if err := r.ensureInit(ctx); err != nil {
		return nil, "", err
	}

	snapID, err := r.latestSnapshotID(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("remote/restic: get %q: %w", path, err)
	}

	// restic dump <snapshot> <path>
	// Restic stores absolute paths in snapshots, so we must prepend the
	// store directory to get the full snapshot path.
	snapshotPath := r.toSnapshotPath(path)
	args := r.buildArgs("dump", snapID, snapshotPath)
	out, err := r.run(ctx, args)
	if err != nil {
		return nil, "", fmt.Errorf("remote/restic: dump %q: %w", path, err)
	}

	return io.NopCloser(bytes.NewReader(out)), snapID, nil
}

// Put writes the content to the local store directory. The change is captured by
// the next Push (restic backup). The file is written to the working tree
// immediately so that it is visible to the store.
//
// expectRev is checked against the latest snapshot ID for conditional writes.
func (r *ResticRemote) Put(ctx context.Context, path string, content io.Reader, expectRev string) (string, error) {
	// Conditional write: check snapshot hasn't changed since List.
	if expectRev != "" {
		latest, err := r.latestSnapshotID(ctx)
		if err == nil && latest != expectRev {
			return "", fmt.Errorf("remote/restic: conflict on %q: expected snapshot %q, got %q",
				path, expectRev, latest)
		}
	}

	data, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("remote/restic: read content: %w", err)
	}

	absPath := filepath.Join(r.storeDir, path)
	if err := resticWriteWorktree(absPath, data); err != nil {
		return "", err
	}

	r.dirty = true
	// Return current snapshot ID as rev (unchanged until Push).
	rev := r.lastSnapID
	return rev, nil
}

// Delete removes the file from the local store directory. The deletion is
// captured by the next Push (restic backup).
func (r *ResticRemote) Delete(ctx context.Context, path string, expectRev string) error {
	if expectRev != "" {
		latest, err := r.latestSnapshotID(ctx)
		if err == nil && latest != expectRev {
			return fmt.Errorf("remote/restic: conflict on %q: expected snapshot %q, got %q",
				path, expectRev, latest)
		}
	}

	absPath := filepath.Join(r.storeDir, path)
	if err := os.Remove(absPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remote/restic: delete %q: %w", path, err)
	}

	r.dirty = true
	return nil
}

// Rename moves a file in the local store directory. The rename is captured by
// the next Push (restic backup).
func (r *ResticRemote) Rename(_ context.Context, from, to string) error {
	fromAbs := filepath.Join(r.storeDir, from)
	toAbs := filepath.Join(r.storeDir, to)

	if err := os.MkdirAll(filepath.Dir(toAbs), storeDirPerm); err != nil {
		return fmt.Errorf("remote/restic: mkdir for rename %q: %w", to, err)
	}
	if err := os.Rename(fromAbs, toAbs); err != nil {
		return fmt.Errorf("remote/restic: rename %q -> %q: %w", from, to, err)
	}

	r.dirty = true
	return nil
}

// Lock returns a no-op unlock. Restic does not support advisory locking; the
// snapshot-based conditional write serves a similar purpose.
func (r *ResticRemote) Lock(_ context.Context) (Unlock, error) {
	return NoopUnlock{}, nil
}

// Close is a no-op for restic (no persistent connections).
func (r *ResticRemote) Close() error { return nil }

// Snapshots returns a list of snapshot IDs, newest first. This is exposed for
// point-in-time recovery and conflict inspection.
func (r *ResticRemote) Snapshots(ctx context.Context) ([]ResticSnapshot, error) {
	if err := r.ensureInit(ctx); err != nil {
		return nil, err
	}
	args := r.buildArgs("snapshots", "--json")
	out, err := r.run(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("remote/restic: snapshots: %w", err)
	}
	var snaps []ResticSnapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		return nil, fmt.Errorf("remote/restic: parse snapshots: %w", err)
	}
	return snaps, nil
}

// Restore downloads an entire snapshot to the given target directory. Restic
// restores the full directory structure including the absolute path of the
// backup source, so the actual files end up under targetDir/storeDir/... This
// method handles the path translation and places files directly under targetDir
// in store-relative layout.
func (r *ResticRemote) Restore(ctx context.Context, snapshotID, targetDir string) error {
	if err := r.ensureInit(ctx); err != nil {
		return err
	}
	// Restore to a staging area first.
	staging := targetDir + ".staging"
	if err := os.MkdirAll(staging, storeDirPerm); err != nil {
		return fmt.Errorf("remote/restic: mkdir staging %q: %w", staging, err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	args := r.buildArgs("restore", snapshotID, "--target", staging)
	if _, err := r.run(ctx, args); err != nil {
		return fmt.Errorf("remote/restic: restore %q: %w", snapshotID, err)
	}

	// Walk the staging area and move store-relative files to targetDir.
	// The restored structure is staging/<abs-store-dir>/... so we need to
	// find the store dir within the staging area and move its contents.
	storeBase := filepath.Base(r.storeDir)
	srcDir := staging
	// Walk up from staging to find the actual store content.
	// The structure is: staging/tmp/.../store/sites/a.gpg
	// We need to find the "store" directory.
	err := filepath.Walk(staging, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == storeBase {
			// Check if this is the right directory by looking at the path.
			// We want the one that has the right basename and is a directory.
			return nil
		}
		return nil
	})
	_ = err // best-effort; the moveAll below will handle missing dirs.

	// Try the known path: staging + absolute storeDir without leading /.
	absTrimmed := strings.TrimPrefix(r.storeDir, "/")
	candidate := filepath.Join(staging, absTrimmed)
	if fi, e := os.Stat(candidate); e == nil && fi.IsDir() {
		srcDir = candidate
	} else {
		// Fallback: walk staging to find a directory matching storeBase.
		//
		// A failure here must not be ignored: srcDir would stay at its
		// initial value and the restore would copy the wrong tree over the
		// store.
		if err := filepath.Walk(staging, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() && info.Name() == storeBase {
				srcDir = path
				return filepath.SkipAll
			}
			return nil
		}); err != nil {
			return fmt.Errorf("remote/restic: locate %q in the restored snapshot: %w", storeBase, err)
		}
	}

	// Copy from srcDir to targetDir.
	return resticMoveAll(srcDir, targetDir)
}

// Forget removes old snapshots according to the given policy. At least one
// policy flag must be set (e.g. "--keep-last 10").
func (r *ResticRemote) Forget(ctx context.Context, policyArgs ...string) error {
	args := r.buildArgs("forget")
	args = append(args, policyArgs...)
	args = append(args, "--prune")
	_, err := r.run(ctx, args)
	if err != nil {
		return fmt.Errorf("remote/restic: forget: %w", err)
	}
	return nil
}

// ---- helpers ----

// buildArgs constructs the base arguments for a restic command, including repo
// and password options.
func (r *ResticRemote) buildArgs(cmd string, extra ...string) []string {
	args := []string{cmd, "--repo", r.repo}
	if r.passwordCmd != "" {
		args = append(args, "--password-command", r.passwordCmd)
	}
	args = append(args, r.extraArgs...)
	args = append(args, extra...)
	return args
}

// run executes a restic command and returns its stdout.
func (r *ResticRemote) run(ctx context.Context, args []string) ([]byte, error) {
	// A fixed binary with arguments assembled by buildArgs; the repository
	// and store paths are operands, never a command line to be parsed.
	cmd := exec.CommandContext(ctx, r.resticPath, args...) //nolint:gosec // fixed binary, arguments built internally.
	cmd.Dir = r.storeDir

	// Build environment: inherit + RESTIC_PASSWORD + extra env.
	cmd.Env = os.Environ()
	if r.password != "" {
		cmd.Env = append(cmd.Env, "RESTIC_PASSWORD="+r.password)
	}
	cmd.Env = append(cmd.Env, r.extraEnv...)

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := bytes.TrimSpace(exitErr.Stderr)
			// Check for "repo not initialised" — our ensureInit should have
			// handled this, but race conditions are possible.
			if bytes.Contains(stderr, []byte("Is there a repository at")) ||
				bytes.Contains(stderr, []byte("no key could be found")) {
				return nil, fmt.Errorf("restic %s: repository not initialised: %s",
					args[0], stderr)
			}
			return nil, fmt.Errorf("restic %s: %s", strings.Join(args, " "), stderr)
		}
		return nil, fmt.Errorf("restic %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// ensureInit checks if the restic repo exists and initialises it if not.
func (r *ResticRemote) ensureInit(ctx context.Context) error {
	if r.initDone {
		return nil
	}
	// Try "restic cat config" to see if the repo exists.
	args := r.buildArgs("cat", "config")
	if _, err := r.run(ctx, args); err != nil {
		// Repo doesn't exist — initialise it.
		initArgs := r.buildArgs("init")
		if _, err := r.run(ctx, initArgs); err != nil {
			return fmt.Errorf("remote/restic: init: %w", err)
		}
	}
	r.initDone = true
	return nil
}

// latestSnapshotID returns the short ID of the latest snapshot, or an error if
// no snapshots exist.
func (r *ResticRemote) latestSnapshotID(ctx context.Context) (string, error) {
	args := r.buildArgs("snapshots", "--latest", "1", "--json")
	out, err := r.run(ctx, args)
	if err != nil {
		return "", err
	}
	var snaps []ResticSnapshot
	if err := json.Unmarshal(out, &snaps); err != nil || len(snaps) == 0 {
		return "", fmt.Errorf("no snapshots found")
	}
	return snaps[0].ShortID, nil
}

// parseSnapshotID extracts the snapshot ID from restic backup output.
// The output contains lines like "snapshot <id> saved".
func parseSnapshotID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// restic 0.17+: "snapshot abc12345 saved"
		if strings.HasPrefix(line, "snapshot ") && strings.Contains(line, " saved") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// toStoreRelative converts an absolute path from a restic snapshot to a
// store-relative path by stripping the storeDir prefix. Restic records the
// absolute path of the backup source, so "restic ls" returns paths like
// "/tmp/store/sites/a.gpg" when the backup source was "/tmp/store". This
// method strips that prefix to produce "sites/a.gpg".
func (r *ResticRemote) toStoreRelative(absPath string) string {
	// Normalise: restic may return "/tmp/store/file" for storeDir="/tmp/store".
	prefix := r.storeDir
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	// Try with leading slash first (most common).
	if strings.HasPrefix(absPath, prefix+"/") {
		return strings.TrimPrefix(absPath, prefix+"/")
	}
	if absPath == prefix {
		return ""
	}
	// Try without leading slash (some restic versions strip it).
	trimmed := strings.TrimPrefix(absPath, "/")
	if strings.HasPrefix(trimmed, strings.TrimPrefix(prefix, "/")+"/") {
		return strings.TrimPrefix(trimmed, strings.TrimPrefix(prefix, "/")+"/")
	}
	// Fallback: if the path doesn't match the storeDir prefix, return as-is
	// after stripping any leading slash. This handles edge cases where the
	// backup was created with a relative path.
	return strings.TrimPrefix(absPath, "/")
}

// toSnapshotPath converts a store-relative path to the absolute path that
// restic uses in the snapshot. This is the inverse of toStoreRelative.
func (r *ResticRemote) toSnapshotPath(relPath string) string {
	return r.storeDir + "/" + relPath
}

// isDotfile reports whether path starts with a dot after the last slash,
// indicating a hidden file that should not be included in sync listings.
func isDotfile(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if len(part) > 0 && part[0] == '.' {
			return true
		}
	}
	return false
}

// resticWriteWorktree writes data to the file at absPath in the working tree,
// creating parent directories as needed. This mirrors GitRemote.writeWorktree.
func resticWriteWorktree(absPath string, data []byte) error {
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, storeDirPerm); err != nil {
		return fmt.Errorf("remote/restic: mkdir %q: %w", dir, err)
	}
	if err := os.WriteFile(absPath, data, storeFilePerm); err != nil {
		return fmt.Errorf("remote/restic: write %q: %w", absPath, err)
	}
	return nil
}

// resticMoveAll copies all files from srcDir to dstDir, preserving the
// relative directory structure. It skips dotfiles and only includes .gpg and
// .age files, consistent with the List filter.
func resticMoveAll(srcDir, dstDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		// Skip dotfiles.
		if isDotfile(rel) {
			return nil
		}
		// Only crypto files.
		ext := filepath.Ext(rel)
		if ext != ".gpg" && ext != ".age" {
			return nil
		}
		dstPath := filepath.Join(dstDir, rel)
		if err := os.MkdirAll(filepath.Dir(dstPath), storeDirPerm); err != nil {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // path comes from walking the snapshot we restored.
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, storeFilePerm) //nolint:gosec // dstPath is joined under dstDir.
	})
}

// ---- JSON types ----

// resticLsEntry represents a single line from "restic ls <snap> --json".
type resticLsEntry struct {
	Type  string `json:"type"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mtime string `json:"mtime"`
	Mode  int64  `json:"mode"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
}

// ResticSnapshot represents a restic snapshot, returned by the Snapshots
// method and by "restic snapshots --json".
type ResticSnapshot struct {
	ID       string   `json:"id"`
	ShortID  string   `json:"short_id"`
	Time     string   `json:"time"`
	Paths    []string `json:"paths"`
	Hostname string   `json:"hostname"`
	Username string   `json:"username"`
	Tags     []string `json:"tags"`
}
