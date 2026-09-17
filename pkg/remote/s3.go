package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Remote talks to S3 and S3-compatible object storage (MinIO, Ceph RGW,
// SeaweedFS, and the clouds that speak the protocol) natively, without
// rclone in between.
//
// What the native client buys over the rclone transport is a genuinely
// conditional write: PutObject with If-Match fails atomically when another
// client changed the object in between, instead of the read-before-write
// race the rclone transport has to live with. The same S3 feature gives the
// advisory lock an atomic acquisition: the lock object is created with
// If-None-Match, so exactly one of two clients racing for it can win.
type S3Remote struct {
	name   string
	bucket string
	prefix string
	device string
	cli    *minio.Client
}

// S3Options configures an S3Remote.
type S3Options struct {
	// Name is the human-readable remote name, e.g. "backup-s3".
	Name string
	// Endpoint is the S3 endpoint: "s3.amazonaws.com", "play.min.io", or
	// a private MinIO host with port. No scheme; Scheme decides TLS.
	Endpoint string
	// Scheme selects the transport: "https" (default) or "http" for a
	// local MinIO or a trusted LAN endpoint.
	Scheme string
	// Region is the bucket's region. MinIO ignores it; AWS needs it.
	Region string
	// Bucket is the S3 bucket the store lives in.
	Bucket string
	// Prefix is the key prefix inside the bucket. Empty means the bucket
	// is dedicated to the store.
	Prefix string
	// AccessKey and SecretKey authenticate. Empty means the credential
	// chain minio-go builds from the environment (AWS_ACCESS_KEY_ID and
	// friends), which is the arrangement production should use.
	AccessKey string
	// SecretKey pairs with AccessKey.
	SecretKey string
	// SessionToken completes temporary credentials, if any.
	SessionToken string
	// Device names this machine in the advisory lock. Empty falls back to
	// the host name, which is what a single-user machine wants.
	Device string
}

// NewS3Remote creates an S3Remote. It validates the options; the bucket's
// existence is not checked here — a wrong bucket surfaces on the first
// operation, with S3's own error.
func NewS3Remote(opts S3Options) (*S3Remote, error) {
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("remote/s3: endpoint is required")
	}
	if opts.Bucket == "" {
		return nil, fmt.Errorf("remote/s3: bucket is required")
	}
	if opts.Scheme == "" {
		opts.Scheme = "https"
	}
	opts.Scheme = strings.ToLower(opts.Scheme)
	if opts.Scheme != "https" && opts.Scheme != "http" {
		return nil, fmt.Errorf("remote/s3: scheme %q: use https or http", opts.Scheme)
	}

	var creds *credentials.Credentials
	if opts.AccessKey != "" {
		creds = credentials.NewStaticV4(opts.AccessKey, opts.SecretKey, opts.SessionToken)
	} else {
		// minio-go signs anonymously when no credentials are given — it
		// does not build the chain itself — so the chain is built here,
		// in the order the AWS tools use: environment, then the shared
		// credentials file, then an instance role.
		creds = credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvAWS{},
			&credentials.FileAWSCredentials{},
			&credentials.IAM{},
		})
	}
	cli, err := minio.New(opts.Endpoint, &minio.Options{
		Creds:  creds,
		Secure: opts.Scheme == "https",
		Region: opts.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("remote/s3: %w", err)
	}
	return &S3Remote{
		name:   opts.Name,
		bucket: opts.Bucket,
		prefix: strings.Trim(opts.Prefix, "/"),
		device: opts.Device,
		cli:    cli,
	}, nil
}

// Name returns the remote name.
func (s *S3Remote) Name() string { return s.name }

// Caps returns the transport capabilities. Put is a real conditional write,
// which is what Atomic means here; the lock is native and atomic; S3 keeps
// old versions only when the bucket has versioning on, which this client
// neither requires nor manages, so History stays off.
func (s *S3Remote) Caps() Caps {
	return Caps{Atomic: true, Locking: true}
}

// key maps a store-relative path to an object key.
func (s *S3Remote) key(p string) string {
	if s.prefix == "" {
		return p
	}
	return s.prefix + "/" + p
}

// normETag strips the quotes S3 wraps ETags in, so revisions compare equal
// no matter which call handed them out.
func normETag(etag string) string {
	return strings.Trim(etag, `"`)
}

// errFromMinio unwraps the S3 error response, if err carries one. minio-go
// returns ErrorResponse by value, wrapped where it is returned at all.
func errFromMinio(err error) (minio.ErrorResponse, bool) {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		return resp, true
	}
	return minio.ErrorResponse{}, false
}

// isNotFound reports whether err is S3's NoSuchKey.
func isNotFound(err error) bool {
	resp, ok := errFromMinio(err)
	return ok && (resp.Code == "NoSuchKey" || resp.StatusCode == http.StatusNotFound)
}

// isPreconditionFailed reports whether err is S3's 412, which is what a
// failed If-Match or If-None-Match looks like.
func isPreconditionFailed(err error) bool {
	resp, ok := errFromMinio(err)
	return ok && (resp.Code == "PreconditionFailed" || resp.Code == "ErrPreconditionFailed" ||
		resp.StatusCode == http.StatusPreconditionFailed)
}

// List returns every store file in the bucket, with the object's ETag as
// the revision the conditional writes compare against.
func (s *S3Remote) List(ctx context.Context) ([]File, error) {
	var files []File
	for object := range s.cli.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    s.key(""),
		Recursive: true,
	}) {
		if object.Err != nil {
			return nil, fmt.Errorf("remote/s3: list %q: %w", s.bucket, object.Err)
		}
		key := object.Key
		// Directory markers are zero-byte objects ending in a slash that
		// some tools leave behind; they are not entries.
		if strings.HasSuffix(key, "/") {
			continue
		}
		if s.prefix != "" {
			key = strings.TrimPrefix(strings.TrimPrefix(key, s.prefix), "/")
		}
		if key == LockFileName {
			continue // the advisory lock is not a store entry.
		}
		files = append(files, File{
			Path:    key,
			Size:    object.Size,
			Rev:     normETag(object.ETag),
			ModTime: object.LastModified,
		})
	}
	return files, nil
}

// Get downloads the object at path and returns its current ETag.
func (s *S3Remote) Get(ctx context.Context, p string) (io.ReadCloser, string, error) {
	obj, err := s.cli.GetObject(ctx, s.bucket, s.key(p), minio.GetObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return nil, "", fmt.Errorf("remote/s3: %q not found", p)
		}
		return nil, "", fmt.Errorf("remote/s3: get %q: %w", p, err)
	}
	// GetObject is lazy; Stat forces the request so a missing key fails
	// here rather than mid-read.
	st, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		if isNotFound(err) {
			return nil, "", fmt.Errorf("remote/s3: %q not found", p)
		}
		return nil, "", fmt.Errorf("remote/s3: stat %q: %w", p, err)
	}
	return obj, normETag(st.ETag), nil
}

// Put uploads content to path. With expectRev set, the write is conditional:
// S3 refuses it with 412 if the object's current ETag differs, so a client
// racing against another writer loses cleanly instead of overwriting it.
func (s *S3Remote) Put(ctx context.Context, p string, content io.Reader, expectRev string) (string, error) {
	// Entries are small; buffering one is the same trade the rclone
	// transport makes, and it buys the exact length S3 wants.
	data, err := io.ReadAll(content)
	if err != nil {
		return "", fmt.Errorf("remote/s3: reading %q: %w", p, err)
	}
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream"}
	if expectRev != "" {
		opts.SetMatchETag(expectRev)
	}
	info, err := s.cli.PutObject(ctx, s.bucket, s.key(p), bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		if isPreconditionFailed(err) {
			return "", fmt.Errorf("remote/s3: conflict on %q: expected rev %q: %w", p, expectRev, err)
		}
		return "", fmt.Errorf("remote/s3: put %q: %w", p, err)
	}
	return normETag(info.ETag), nil
}

// Delete removes the object at path. S3 has no conditional delete, so the
// revision check is read-then-delete — the same shape as the rclone
// transport. A delete that races a concurrent put costs one extra object
// until the next sync converges; it never loses data.
func (s *S3Remote) Delete(ctx context.Context, p string, expectRev string) error {
	key := s.key(p)
	if expectRev != "" {
		obj, err := s.cli.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
		if err != nil {
			if isNotFound(err) {
				return fmt.Errorf("remote/s3: delete %q: already gone", p)
			}
			return fmt.Errorf("remote/s3: delete %q: %w", p, err)
		}
		if normETag(obj.ETag) != expectRev {
			return fmt.Errorf("remote/s3: conflict on %q: expected rev %q, got %q", p, expectRev, normETag(obj.ETag))
		}
	}
	if err := s.cli.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("remote/s3: delete %q: %w", p, err)
	}
	return nil
}

// Rename moves an object server-side: CopyObject then remove the source.
// No re-upload, and the content never leaves the storage.
func (s *S3Remote) Rename(ctx context.Context, from, to string) error {
	src := minio.CopySrcOptions{Bucket: s.bucket, Object: s.key(from)}
	dst := minio.CopyDestOptions{Bucket: s.bucket, Object: s.key(to)}
	if _, err := s.cli.CopyObject(ctx, dst, src); err != nil {
		return fmt.Errorf("remote/s3: rename %q -> %q: %w", from, to, err)
	}
	if err := s.cli.RemoveObject(ctx, s.bucket, s.key(from), minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("remote/s3: rename %q -> %q: removing source: %w", from, to, err)
	}
	return nil
}

// Lock takes the advisory lock atomically: the lock object is created with
// If-None-Match, so of two clients racing for it exactly one wins. A lock
// whose holder died is recovered by TTL, same as the rclone transport's
// lock; the difference is only in how the lock is taken.
func (s *S3Remote) Lock(ctx context.Context) (Unlock, error) {
	device := s.device
	if device == "" {
		if host, err := os.Hostname(); err == nil && host != "" {
			device = host
		} else {
			device = "unknown"
		}
	}

	ours := advisoryLock{Device: device, TS: time.Now(), TTL: DefaultLockTTL}
	body := ours.marshal()
	opts := minio.PutObjectOptions{ContentType: "text/plain"}
	opts.SetMatchETagExcept("*") // If-None-Match: create-only.

	_, lockErr := s.cli.PutObject(ctx, s.bucket, s.key(LockFileName), bytes.NewReader(body), int64(len(body)), opts)
	if lockErr == nil {
		return &s3Unlock{remote: s, device: device}, nil
	}
	if !isPreconditionFailed(lockErr) {
		return nil, fmt.Errorf("remote/s3: lock: %w", lockErr)
	}

	// The lock exists. It is either held or stale; only its TTL can tell.
	rc, _, getErr := s.Get(ctx, LockFileName)
	if getErr != nil {
		return nil, fmt.Errorf("remote/s3: lock is held and unreadable: %w (lock write error: %v)", getErr, lockErr)
	}
	raw, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if readErr != nil {
		return nil, fmt.Errorf("remote/s3: reading lock: %w", readErr)
	}
	held, parseErr := parseAdvisoryLock(raw)
	if parseErr != nil {
		// An unreadable lock is treated as live: removing it is a human
		// decision, not an automatic guess.
		return nil, &LockHeldError{Remote: s.name}
	}
	if !held.stale(time.Now()) {
		return nil, &LockHeldError{Remote: s.name, Lock: held}
	}

	// Stale: remove it and try once more. The create-only write keeps the
	// steal safe — if another client re-took the lock in between, it is
	// that client's write that wins, not this one's.
	if err := s.cli.RemoveObject(ctx, s.bucket, s.key(LockFileName), minio.RemoveObjectOptions{}); err != nil && !isNotFound(err) {
		return nil, fmt.Errorf("remote/s3: removing stale lock: %w", err)
	}
	if _, err := s.cli.PutObject(ctx, s.bucket, s.key(LockFileName), bytes.NewReader(body), int64(len(body)), opts); err != nil {
		if isPreconditionFailed(err) {
			return nil, &LockHeldError{Remote: s.name}
		}
		return nil, fmt.Errorf("remote/s3: lock: %w", err)
	}
	return &s3Unlock{remote: s, device: device}, nil
}

// s3Unlock releases the S3 advisory lock.
type s3Unlock struct {
	remote *S3Remote
	device string
}

// Unlock deletes the lock object.
func (u *s3Unlock) Unlock(ctx context.Context) error {
	if err := u.remote.cli.RemoveObject(ctx, u.remote.bucket, u.remote.key(LockFileName), minio.RemoveObjectOptions{}); err != nil && !isNotFound(err) {
		return fmt.Errorf("remote/s3: unlock: %w", err)
	}
	return nil
}

// Close releases transport resources; the S3 client holds none that matter.
func (s *S3Remote) Close() error { return nil }
