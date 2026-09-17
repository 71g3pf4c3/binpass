package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/71g3pf4c3/binpass/internal/config"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	miniomodule "github.com/testcontainers/testcontainers-go/modules/minio"
)

// startMinIOForSync launches a real MinIO container and returns its address
// plus a fresh bucket for the test's store, skipping when no Docker daemon
// answers — CI installs one, a laptop without the socket skips, the same
// contract the golden suite has with pass.
func startMinIOForSync(t *testing.T) (addr, bucket string) {
	t.Helper()
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("no Docker socket: MinIO container tests need one")
	}
	ctx := context.Background()
	container, err := miniomodule.Run(ctx, "quay.io/minio/minio:latest")
	if err != nil {
		t.Skipf("MinIO container did not start: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	addr, err = container.ConnectionString(ctx)
	require.NoError(t, err)

	cli, err := minio.New(addr, &minio.Options{
		Creds:  credentials.NewStaticV4("minioadmin", "minioadmin", ""),
		Secure: false,
	})
	require.NoError(t, err)
	// S3 bucket names allow nothing but lower-case letters, digits and
	// hyphens, and test names carry underscores.
	bucket = "e2e-" + strings.ToLower(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, strings.TrimPrefix(t.Name(), "Test")))
	require.NoError(t, cli.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}))
	return addr, bucket
}

// s3RemoteConfig builds the config a user would write for a native S3
// remote, including the http:// form local MinIO needs.
func s3RemoteConfig(addr, bucket string) map[string]config.RemoteConfig {
	return map[string]config.RemoteConfig{
		"backup": {Type: "s3", URL: "http://" + addr, Bucket: bucket},
	}
}

// TestS3Sync_E2E drives the whole sync engine through the native S3
// transport against a real MinIO: a push, a pull on the second device, and
// a genuine edit-versus-edit conflict that must leave both versions on disk.
func TestS3Sync_E2E(t *testing.T) {
	addr, bucket := startMinIOForSync(t)
	// Credentials ride the environment, exactly the production path: the
	// config file has no place for a secret key, the env chain is how the
	// native transport authenticates.
	t.Setenv("AWS_ACCESS_KEY_ID", "minioadmin")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "minioadmin")

	appA := newTestApp(t)
	appB := newTestApp(t)
	// Device B reads what device A encrypts: one identity, shared the way
	// a team shares its store key. The store resolves it lazily at decrypt
	// time, so swapping the config after the store exists is enough.
	appB.Cfg.Identity = appA.Cfg.Identity

	appA.Cfg.Remotes = s3RemoteConfig(addr, bucket)
	appB.Cfg.Remotes = s3RemoteConfig(addr, bucket)

	ctx := context.Background()

	// A creates and pushes.
	appA.activate(t)
	appA.set(t, "github.com/alice", "hunter2\n")
	require.NoError(t, appA.runSync(ctx, "backup", false))

	// B pulls and has the entry.
	appB.activate(t)
	require.NoError(t, appB.runSync(ctx, "backup", false))
	bs, err := appB.Store()
	require.NoError(t, err)
	sec, err := bs.Get("github.com/alice")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", sec.Password())

	// Both devices edit the same entry offline.
	appA.set(t, "shared/entry", "version-from-a\n")
	appB.set(t, "shared/entry", "version-from-b\n")

	// A syncs its edit first.
	appA.activate(t)
	require.NoError(t, appA.runSync(ctx, "backup", false))

	// B's edit now conflicts with what A pushed; the sync must detect it,
	// keep both versions, and not lose either.
	appB.activate(t)
	appB.out.Reset()
	require.NoError(t, appB.runSync(ctx, "backup", false))

	assert.Contains(t, appB.out.String(), "conflict", "the sync reports the conflict")

	matches, err := filepath.Glob(filepath.Join(appB.dir, "shared", "entry.conflict-*.age"))
	require.NoError(t, err)
	require.Len(t, matches, 1, "device B keeps its local version as a conflict file")

	// The remote version is what the plain path holds now.
	sec, err = bs.Get("shared/entry")
	require.NoError(t, err)
	assert.Equal(t, "version-from-a", sec.Password(), "the remote version takes the plain path")
}
