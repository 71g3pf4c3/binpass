package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	device     string
	// run executes one rclone invocation. It is a field so tests can
	// substitute an in-memory fake for the real binary, the same way the
	// golden suite substitutes the real pass.
	run func(ctx context.Context, args []string, stdin io.Reader) ([]byte, error)
}

// RcloneOptions configures an RcloneRemote.
type RcloneOptions struct {
	// Name is the human-readable name for this remote (for display and logging).
	Name string
	// Remote is the rclone remote:path, e.g. "mybucket:password-store" or
	// "gdrive:binpass". Must end with a colon if it refers to the root.
	Remote string
	// Device identifies this machine in the advisory lock. The sync engine
	// passes the same device ID it stores in state.db, so a lock names the
	// device the conflict files name. Empty falls back to the hostname.
	Device string
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
		device:     opts.Device,
		run:        realRclone(p),
	}, nil
}

// realRclone returns the default runner: one exec per invocation, with
// CombinedOutput so rclone's own diagnostics reach the error message.
func realRclone(path string) func(ctx context.Context, args []string, stdin io.Reader) ([]byte, error) {
	return func(ctx context.Context, args []string, stdin io.Reader) ([]byte, error) {
		cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // fixed binary, arguments built internally.
		cmd.Stdin = stdin
		out, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("rclone %s: %s: %w", strings.Join(args, " "), out, err)
		}
		return out, nil
	}
}

// Name returns the human-readable name.
func (r *RcloneRemote) Name() string { return r.name }

// Caps returns the capabilities of rclone-backed storage. Rclone provides
// atomic writes through S3's If-Match when the backend supports it; for
// other backends we report weak atomicity and rely on verify-after-write.
// Advisory locking is a lock file in the remote root, which every rclone
// backend can carry.
func (r *RcloneRemote) Caps() Caps {
	return Caps{
		Atomic:     false, // Conservatively false; S3 could be true with If-Match.
		WeakAtomic: true,  // Rclone verifies uploads by default.
		History:    true,  // S3 has versioning; others may not.
		Locking:    true,
		Rename:     false, // Cloud storages cannot rename in place.
		Watch:      false,
	}
}

// List returns all .gpg and .age files on the remote.
func (r *RcloneRemote) List(ctx context.Context) ([]File, error) {
	// rclone lsf -R --format "ps" --separator "\t" remote:path
	//
	// -R is not optional: without it lsf lists the top level only, and a
	// store whose entries live in directories ("github.com/alice.age")
	// would look empty to the sync engine. Directories show up in the
	// output as lines with a negative size; IsStoreContent filters them
	// out along with everything else that is not a store file.
	out, err := r.rclone(ctx, "lsf",
		"-R",
		"--format", "ps",
		"--separator", "\t",
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
	if _, err := r.run(ctx, []string{"rcat", remotePath}, bytes.NewReader(data)); err != nil {
		return "", fmt.Errorf("remote/rclone: put %q: %w", path, err)
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

// Lock acquires the advisory lock: a .binpass.lock file in the remote root.
//
// The protocol is write, read back, compare — the best a storage without
// compare-and-swap can do. Two clients that race for the same expired lock
// can both believe they hold it in the window between one's read-back and
// the other's write; the TTL means the damage is bounded, and conditional
// writes (expectRev) still catch a lost update at the file level.
//
// A lock whose holder died is recovered by expiry: once ts + ttl is in the
// past, the next client overwrites it.
func (r *RcloneRemote) Lock(ctx context.Context) (Unlock, error) {
	device := r.device
	if device == "" {
		if host, err := os.Hostname(); err == nil && host != "" {
			device = host
		} else {
			device = "unknown"
		}
	}
	lockPath := r.remote + "/" + LockFileName
	now := time.Now()

	// A read error here is "no lock yet" as often as it is a broken
	// transport; rather than guess, fall through to the write, which fails
	// loudly on a transport that is genuinely down.
	if data, err := r.run(ctx, []string{"cat", lockPath}, nil); err == nil {
		if held, perr := parseAdvisoryLock(data); perr == nil && !held.stale(now) && held.Device != device {
			return nil, &LockHeldError{Remote: r.name, Lock: held}
		}
	}

	ours := advisoryLock{Device: device, TS: now, TTL: DefaultLockTTL}
	if _, err := r.run(ctx, []string{"rcat", lockPath}, bytes.NewReader(ours.marshal())); err != nil {
		return nil, fmt.Errorf("remote/rclone: lock: %w", err)
	}

	// The read-back is what turns a blind overwrite into a lock: if another
	// client's content came back, they won the race and we must not touch
	// the store.
	back, err := r.run(ctx, []string{"cat", lockPath}, nil)
	if err != nil {
		return nil, fmt.Errorf("remote/rclone: lock verify: %w", err)
	}
	if !bytes.Equal(back, ours.marshal()) {
		var holder advisoryLock
		if parsed, perr := parseAdvisoryLock(back); perr == nil {
			holder = parsed
		}
		return nil, &LockHeldError{Remote: r.name, Lock: holder}
	}
	return rcloneUnlock{r: r, device: device}, nil
}

// rcloneUnlock releases a lock acquired by RcloneRemote.Lock. It deletes the
// lock file only when it still names this device, so it never removes a lock
// another client legitimately took over after ours expired.
type rcloneUnlock struct {
	r      *RcloneRemote
	device string
}

// Unlock releases the advisory lock.
func (u rcloneUnlock) Unlock(ctx context.Context) error {
	lockPath := u.r.remote + "/" + LockFileName
	data, err := u.r.run(ctx, []string{"cat", lockPath}, nil)
	if err != nil {
		// The lock is gone; releasing an absent lock is success, the
		// same way closing an already-closed file is.
		return nil
	}
	held, perr := parseAdvisoryLock(data)
	if perr != nil || held.Device != u.device {
		return nil
	}
	if _, err := u.r.run(ctx, []string{"delete", lockPath}, nil); err != nil {
		return fmt.Errorf("remote/rclone: unlock: %w", err)
	}
	return nil
}

// Close is a no-op for rclone.
func (r *RcloneRemote) Close() error { return nil }

// rclone executes an rclone command and returns its stdout.
func (r *RcloneRemote) rclone(ctx context.Context, args ...string) ([]byte, error) {
	return r.run(ctx, args, nil)
}
