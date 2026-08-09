// Package remote defines the transport interface for binpass synchronisation
// and provides built-in implementations for git, Google Drive, Yandex.Disk,
// WebDAV, and S3.
//
// The [Remote] interface is the same for all transports; its [Caps] method
// advertises what the transport can do so that the sync engine can adapt its
// strategy (for example, adding verify-after-write when the transport lacks
// atomicity).
package remote

import (
	"context"
	"io"
	"time"
)

// Caps describes the capabilities of a Remote transport. The sync engine uses
// these to decide whether to add extra safety measures like verify-after-write
// or advisory locking.
type Caps struct {
	// Atomic reports whether Put replaces the file atomically. S3 with
	// If-Match is atomic; Drive and WebDAV are not.
	Atomic bool
	// WeakAtomic reports whether the transport provides a best-effort atomic
	// Put that should be verified with a subsequent read (verify-after-write).
	WeakAtomic bool
	// History reports whether the transport keeps old revisions. Git and S3
	// do; Drive does (through revision IDs).
	History bool
	// Locking reports whether the transport supports explicit advisory locks
	// (e.g. a .binpass.lock file with TTL).
	Locking bool
	// Rename reports whether the transport can rename a file without
	// re-uploading it. Git can; cloud storages generally cannot.
	Rename bool
	// Watch reports whether the transport can push change notifications
	// instead of requiring polling.
	Watch bool
}

// File is a file listed by a Remote transport.
type File struct {
	// Path is the store-relative path, for example "github.com/alice.gpg".
	Path string
	// Size is the file size in bytes.
	Size int64
	// ModTime is the modification time, or the zero time if unavailable.
	ModTime time.Time
	// Rev is the transport-specific revision: a git SHA, an S3 ETag, a Drive
	// revision, and so on. It is passed to Put/Delete to implement conditional
	// writes.
	Rev string
}

// Remote is the transport interface for synchronisation (§8.2). One
// implementation serves git, Google Drive, Yandex.Disk, WebDAV, and S3; the
// sync engine treats them identically and adapts its behaviour using Caps.
type Remote interface {
	// Name returns a human-readable name for this remote, for example
	// "origin" or "gdrive".
	Name() string

	// Caps returns the capabilities of this transport.
	Caps() Caps

	// List returns all files currently on the remote. The sync engine uses
	// this to build a remote snapshot.
	List(ctx context.Context) ([]File, error)

	// Get downloads the file at path. It returns the content, the current
	// revision, and any error.
	Get(ctx context.Context, path string) (content io.ReadCloser, rev string, err error)

	// Put uploads content to path. If expectRev is non-empty, the upload
	// must fail if the current revision does not match (conditional write).
	// It returns the new revision.
	Put(ctx context.Context, path string, content io.Reader, expectRev string) (rev string, err error)

	// Delete removes the file at path. If expectRev is non-empty, the delete
	// must fail if the current revision does not match.
	Delete(ctx context.Context, path string, expectRev string) error

	// Rename moves a file from one path to another. Transports that do not
	// support Rename should return an error; the sync engine will fall back
	// to Get + Put + Delete.
	Rename(ctx context.Context, from, to string) error

	// Lock acquires an advisory lock on the remote store. If the transport
	// does not support locking, it returns a no-op Unlock.
	Lock(ctx context.Context) (Unlock, error)

	// Close releases any resources held by the remote (open connections,
	// temporary files, and so on).
	Close() error
}

// Unlock releases an advisory lock acquired by [Remote.Lock].
type Unlock interface {
	Unlock(ctx context.Context) error
}

// NoopUnlock is a no-op lock release for transports without advisory locking.
type NoopUnlock struct{}

// Unlock does nothing.
func (NoopUnlock) Unlock(_ context.Context) error { return nil }

// FromConfig creates a Remote from a type string and a map of options.
// Supported types: "git", "restic", "s3", "gdrive", "yandex", "webdav".
// Cloud remotes (s3, gdrive, yandex, webdav) are backed by rclone.
func FromConfig(remoteType string, opts map[string]string) (Remote, error) {
	switch remoteType {
	case "git":
		name := opts["name"]
		if name == "" {
			name = "origin"
		}
		dir := opts["dir"]
		return NewGitRemote(GitOptions{
			Name: name,
			Dir:  dir,
		})
	case "restic":
		name := opts["name"]
		if name == "" {
			name = "restic"
		}
		return NewResticRemote(ResticOptions{
			Name:            name,
			Repo:            opts["repo"],
			Password:        opts["password"],
			PasswordCommand: opts["password_command"],
			StoreDir:        opts["store_dir"],
		})
	case "s3", "gdrive", "yandex", "webdav":
		name := opts["name"]
		if name == "" {
			name = remoteType
		}
		remote := opts["remote"]
		if remote == "" {
			remote = opts["url"]
		}
		return NewRcloneRemote(RcloneOptions{
			Name:   name,
			Remote: remote,
		})
	default:
		return nil, ErrUnknownRemote
	}
}

// ErrUnknownRemote is returned when the remote type is not recognised.
var ErrUnknownRemote = errUnknownRemote("")

type errUnknownRemote string

func (e errUnknownRemote) Error() string {
	return "remote: unknown type " + string(e)
}

// Permissions for anything a transport writes into the password store.
//
// pass creates entries with a 077 umask, and so does pkg/storage. A transport
// writing the same files at 0644 would quietly widen access to every entry it
// synchronised: the ciphertext of a whole store, readable by any other user
// on the machine.
const (
	// storeFilePerm is the mode for an entry written into the store.
	storeFilePerm = 0o600
	// storeDirPerm is the mode for a directory created inside the store.
	storeDirPerm = 0o700
)
