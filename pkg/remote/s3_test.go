package remote

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	miniomodule "github.com/testcontainers/testcontainers-go/modules/minio"
)

// skipWithoutDocker skips a test when no Docker daemon answers, which is the
// lot of a machine without the socket — the same silent-skip trade the
// golden tests make for pass, so CI installs what it needs and asserts.
func skipWithoutDocker(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return
	}
	t.Skip("no Docker socket: MinIO container tests need one")
}

// startMinIO launches a real MinIO in a container and returns its address
// (host:port). The bucket is created by the caller: fixture needs differ.
func startMinIO(t *testing.T) string {
	t.Helper()
	skipWithoutDocker(t)
	ctx := context.Background()
	container, err := miniomodule.Run(ctx, "quay.io/minio/minio:latest")
	if err != nil {
		t.Skipf("MinIO container did not start: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	addr, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	return addr
}

// newS3Client returns a raw minio client against the test server, for
// setting up state the remote under test must handle.
func newS3Client(t *testing.T, addr string) *minio.Client {
	t.Helper()
	cli, err := minio.New(addr, &minio.Options{
		Creds:  credentials.NewStaticV4("minioadmin", "minioadmin", ""),
		Secure: false,
	})
	require.NoError(t, err)
	return cli
}

// newTestS3Remote builds an S3Remote against the test server with a fresh
// bucket and the given device name.
func newTestS3Remote(t *testing.T, addr, device string) *S3Remote {
	t.Helper()
	ctx := context.Background()
	cli := newS3Client(t, addr)
	// S3 bucket names allow nothing but lower-case letters, digits and
	// hyphens, and test names carry underscores.
	bucket := "store-" + strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, strings.TrimPrefix(t.Name(), "Test"))
	require.NoError(t, cli.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}))
	r, err := NewS3Remote(S3Options{
		Name:      "test-s3",
		Endpoint:  addr,
		Scheme:    "http",
		Bucket:    bucket,
		Device:    device,
		AccessKey: "minioadmin",
		SecretKey: "minioadmin",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestS3Remote_Validation(t *testing.T) {
	_, err := NewS3Remote(S3Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "endpoint")

	_, err = NewS3Remote(S3Options{Endpoint: "s3.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket")

	_, err = NewS3Remote(S3Options{Endpoint: "s3.example.com", Bucket: "b", Scheme: "ftp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestS3Remote_RoundTrip(t *testing.T) {
	addr := startMinIO(t)
	if addr == "" {
		return
	}
	r := newTestS3Remote(t, addr, "dev1")
	ctx := context.Background()

	rev, err := r.Put(ctx, "github.com/alice.age", strings.NewReader("ciphertext-one"), "")
	require.NoError(t, err)
	assert.NotEmpty(t, rev, "Put returns the new ETag")

	files, err := r.List(ctx)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "github.com/alice.age", files[0].Path)
	assert.Equal(t, int64(len("ciphertext-one")), files[0].Size)
	assert.Equal(t, rev, files[0].Rev, "List sees the revision Put returned")

	rc, gotRev, err := r.Get(ctx, "github.com/alice.age")
	require.NoError(t, err)
	content, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "ciphertext-one", string(content))
	assert.Equal(t, rev, gotRev)

	require.NoError(t, r.Delete(ctx, "github.com/alice.age", rev))
	files, err = r.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestS3Remote_ConditionalWrite(t *testing.T) {
	addr := startMinIO(t)
	if addr == "" {
		return
	}
	r := newTestS3Remote(t, addr, "dev1")
	ctx := context.Background()

	rev, err := r.Put(ctx, "bank.age", strings.NewReader("v1"), "")
	require.NoError(t, err)

	// A write that expects a revision nobody else saw still changes the
	// object, so the ETag must move; same content would reuse the ETag.
	newRev, err := r.Put(ctx, "bank.age", strings.NewReader("v2"), rev)
	require.NoError(t, err)
	assert.NotEqual(t, rev, newRev, "different content, different ETag")

	// A stale revision is refused, not overwritten.
	_, err = r.Put(ctx, "bank.age", strings.NewReader("v3"), rev)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflict")

	// The refused write left the object at the version the winner wrote.
	rc, _, err := r.Get(ctx, "bank.age")
	require.NoError(t, err)
	content, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "v2", string(content))

	// Delete consults the revision too.
	err = r.Delete(ctx, "bank.age", rev)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflict")
}

func TestS3Remote_PrefixAndLockVisibility(t *testing.T) {
	addr := startMinIO(t)
	if addr == "" {
		return
	}
	r := newTestS3Remote(t, addr, "dev1")
	ctx := context.Background()

	// The lock object and directory markers are not entries.
	unlock, err := r.Lock(ctx)
	require.NoError(t, err)
	files, err := r.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, files, "the lock object is not a store entry")
	require.NoError(t, unlock.Unlock(ctx))

	// A prefix confines the store to its corner of the bucket.
	cli := newS3Client(t, addr)
	bucket := r.bucket
	_, err = cli.PutObject(ctx, bucket, "unrelated/file", strings.NewReader("x"), 1, minio.PutObjectOptions{})
	require.NoError(t, err)

	prefixed, err := NewS3Remote(S3Options{
		Name:      "p",
		Endpoint:  addr,
		Scheme:    "http",
		Bucket:    bucket,
		Prefix:    "binpass",
		AccessKey: "minioadmin",
		SecretKey: "minioadmin",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = prefixed.Close() })

	_, err = prefixed.Put(ctx, "entry.age", strings.NewReader("y"), "")
	require.NoError(t, err)
	files, err = prefixed.List(ctx)
	require.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "entry.age", files[0].Path, "the prefix is stripped from the path the sync engine sees")
}

func TestS3Remote_AdvisoryLock(t *testing.T) {
	addr := startMinIO(t)
	if addr == "" {
		return
	}
	holder := newTestS3Remote(t, addr, "holder")
	rival := &S3Remote{name: "rival", bucket: holder.bucket, prefix: holder.prefix, device: "rival", cli: holder.cli}
	ctx := context.Background()

	unlock, err := holder.Lock(ctx)
	require.NoError(t, err)

	_, err = rival.Lock(ctx)
	require.Error(t, err)
	var held *LockHeldError
	require.ErrorAs(t, err, &held)
	assert.Equal(t, "holder", held.Lock.Device)

	require.NoError(t, unlock.Unlock(ctx))
	unlock2, err := rival.Lock(ctx)
	require.NoError(t, err)
	require.NoError(t, unlock2.Unlock(ctx))
}

func TestS3Remote_StaleLockIsRecovered(t *testing.T) {
	addr := startMinIO(t)
	if addr == "" {
		return
	}
	r := newTestS3Remote(t, addr, "dev1")
	ctx := context.Background()

	// A lock left behind by a machine that died: past its TTL.
	stale := advisoryLock{Device: "ghost", TS: time.Now().Add(-2 * DefaultLockTTL), TTL: DefaultLockTTL}
	_, err := r.cli.PutObject(ctx, r.bucket, r.key(LockFileName), strings.NewReader(string(stale.marshal())), int64(len(stale.marshal())), minio.PutObjectOptions{})
	require.NoError(t, err)

	unlock, err := r.Lock(ctx)
	require.NoError(t, err, "a lock past its TTL is recoverable")
	require.NoError(t, unlock.Unlock(ctx))
}

func TestS3Remote_Caps(t *testing.T) {
	addr := startMinIO(t)
	if addr == "" {
		return
	}
	r := newTestS3Remote(t, addr, "dev1")
	caps := r.Caps()
	assert.True(t, caps.Atomic, "PutObject with If-Match is a real conditional write")
	assert.True(t, caps.Locking)
	assert.False(t, caps.WeakAtomic)
}
