package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// RcloneRemote is a Remote backed by any storage that rclone supports. It
// delegates all I/O to the system rclone binary, so the user's rclone.conf
// (with OAuth tokens, encryption, etc.) is used automatically.
//
// This single implementation serves S3, Google Drive, Yandex.Disk, and WebDAV
// by varying the remote type in the rclone config. The sync engine treats all
// rclone-backed remotes identically and adapts its behaviour using Caps.
type RcloneRemote struct {
	name       string
	remote     string // e.g. "mybucket:" or "gdrive:binpass"
	rclonePath string
}

// RcloneOptions configures an RcloneRemote.
type RcloneOptions struct {
	// Name is the human-readable name for this remote (for display and logging).
	Name string
	// Remote is the rclone remote:path, e.g. "mybucket:password-store" or
	// "gdrive:binpass". Must end with a colon if it refers to the root.
	Remote string
}

// NewRcloneRemote creates a new rclone-backed remote. It verifies that the
// rclone binary is available on PATH.
func NewRcloneRemote(opts RcloneOptions) (*RcloneRemote, error) {
	p, err := exec.LookPath("rclone")
	if err != nil {
		return nil, fmt.Errorf("remote/rclone: rclone not found on PATH: %w", err)
	}
	return &RcloneRemote{
		name:       opts.Name,
		remote:     opts.Remote,
		rclonePath: p,
	}, nil
}

// Name returns the human-readable name.
func (r *RcloneRemote) Name() string { return r.name }

// Caps returns the capabilities of rclone-backed storage. Rclone provides
// atomic writes through S3's If-Match when the backend supports it; for
// other backends we report weak atomicity and rely on verify-after-write.
func (r *RcloneRemote) Caps() Caps {
	return Caps{
		Atomic:     false, // Conservatively false; S3 could be true with If-Match.
		WeakAtomic: true,  // Rclone verifies uploads by default.
		History:    true,  // S3 has versioning; others may not.
		Locking:    false,
		Rename:     false, // Cloud storages cannot rename in place.
		Watch:      false,
	}
}

// List returns all .gpg and .age files on the remote.
func (r *RcloneRemote) List(ctx context.Context) ([]File, error) {
	// rclone lsf --format "ps" --separator "\t" remote:path
	out, err := r.rclone(ctx, "lsf",
		"--format", "ps",
		"--separator", "\t",
		"--files-from-raw", "/dev/stdin", // unused, just listing all
		r.remote,
	)
	if err != nil {
		return nil, fmt.Errorf("remote/rclone: list: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}

	var files []File
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		parts := strings.SplitN(string(line), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		path := parts[0]
		// Entries and the tomb container. A closed LUKS or sparse bundle
		// store is only the container, so an extension check alone reports
		// such a store as empty.
		if !IsStoreContent(path) || storeDotfiles[filepath.Base(path)] {
			continue
		}
		// The listing comes from the cloud backend, not from us.
		if err := CheckPath(path); err != nil {
			return nil, err
		}
		size, _ := strconv.ParseInt(parts[1], 10, 64)
		files = append(files, File{
			Path: path,
			Size: size,
			Rev:  fmt.Sprintf("%d", size), // Use size as weak rev when no ETag available.
		})
	}
	return files, nil
}

// Get downloads a file from the remote.
func (r *RcloneRemote) Get(ctx context.Context, path string) (io.ReadCloser, string, error) {
	remotePath := r.remote + "/" + path
	out, err := r.rclone(ctx, "cat", remotePath)
	if err != nil {
		return nil, "", fmt.Errorf("remote/rclone: get %q: %w", path, err)
	}
	// Use the output length as a weak rev.
	rev := fmt.Sprintf("%d", len(out))
	return io.NopCloser(bytes.NewReader(out)), rev, nil
}

// Put uploads a file to the remote. If expectRev is non-empty, it first checks
// that the existing file matches (conditional write). For S3, rclone uses
// --s3-upload-cutoff and multipart uploads; conditional writes are not
// natively supported for all backends, so this is best-effort.
func (r *RcloneRemote) Put(ctx context.Context, path string, content io.Reader, expectRev string) (string, error) {
	remotePath := r.remote + "/" + path

	// Conditional write: check the current file matches.
	if expectRev != "" {
		_, currentRev, err := r.Get(ctx, path)
		if err == nil && currentRev != expectRev {
			return "", fmt.Errorf("remote/rclone: conflict on %q: expected rev %q, got %q", path, expectRev, currentRev)
		}
	}

	// Read content and pipe to rclone via stdin.
	data, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("remote/rclone: read content: %w", err)
	}

	// Write to a temp file for rclone copyto (rclone cannot read from stdin for copyto).
	// Use rclone rcat instead which reads from stdin.
	// A fixed binary; remotePath is the configured remote plus a store
	// path, passed as a single operand.
	cmd := exec.CommandContext(ctx, r.rclonePath, "rcat", remotePath) //nolint:gosec // fixed binary, arguments built internally.
	cmd.Stdin = bytes.NewReader(data)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("remote/rclone: put %q: %s: %w", path, out, err)
	}

	rev := fmt.Sprintf("%d", len(data))
	return rev, nil
}

// Delete removes a file from the remote.
func (r *RcloneRemote) Delete(ctx context.Context, path string, expectRev string) error {
	remotePath := r.remote + "/" + path

	if expectRev != "" {
		_, currentRev, err := r.Get(ctx, path)
		if err == nil && currentRev != expectRev {
			return fmt.Errorf("remote/rclone: conflict on %q: expected rev %q, got %q", path, expectRev, currentRev)
		}
	}

	if _, err := r.rclone(ctx, "delete", remotePath); err != nil {
		return fmt.Errorf("remote/rclone: delete %q: %w", path, err)
	}
	return nil
}

// Rename is not natively supported by cloud storage; fall back to
// copy + delete.
func (r *RcloneRemote) Rename(ctx context.Context, from, to string) error {
	fromPath := r.remote + "/" + from
	toPath := r.remote + "/" + to

	// rclone moveto = copy + delete source.
	if _, err := r.rclone(ctx, "moveto", fromPath, toPath); err != nil {
		return fmt.Errorf("remote/rclone: rename %q -> %q: %w", from, to, err)
	}
	return nil
}

// Lock returns a no-op unlock since rclone has no advisory locking.
func (r *RcloneRemote) Lock(_ context.Context) (Unlock, error) {
	return NoopUnlock{}, nil
}

// Close is a no-op for rclone.
func (r *RcloneRemote) Close() error { return nil }

// rclone executes an rclone command and returns its stdout.
func (r *RcloneRemote) rclone(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.rclonePath, args...) //nolint:gosec // fixed binary, arguments built internally.
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rclone %s: %s: %w", strings.Join(args, " "), out, err)
	}
	return out, nil
}
