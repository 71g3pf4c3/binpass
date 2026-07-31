// Package integration_test drives the full binpassd stack — PostgreSQL, the
// gRPC controllers, the use cases, the persistent repositories, and the gRPC
// client remote — through a realistic register → sync → second-device flow.
//
// It requires Docker (testcontainers). Skip with `go test -short`.
package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"testing"
	"time"

	binpassv1 "github.com/71g3pf4c3/binpass/server/gen/v1"
	"github.com/71g3pf4c3/binpass/server/client/remote"
	grpcv1 "github.com/71g3pf4c3/binpass/server/internal/controller/grpc/v1"
	"github.com/71g3pf4c3/binpass/server/internal/usecase"
	"github.com/71g3pf4c3/binpass/server/internal/usecase/repo/blob"
	"github.com/71g3pf4c3/binpass/server/internal/usecase/repo/eventbus"
	"github.com/71g3pf4c3/binpass/server/internal/usecase/repo/persistent"
	"github.com/71g3pf4c3/binpass/server/pkg/argon2"
	"github.com/71g3pf4c3/binpass/server/pkg/jwt"
	"github.com/71g3pf4c3/binpass/server/pkg/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// staticToken is a TokenSource returning a fixed access token.
type staticToken struct{ tok string }

func (s staticToken) Token(context.Context) (string, error) { return s.tok, nil }

// schema is applied directly (mirrors migrations/0001_init.up.sql) to avoid a
// migrate driver dependency inside the test.
const schema = `
CREATE TABLE users (id UUID PRIMARY KEY, login TEXT UNIQUE NOT NULL, auth_hash TEXT NOT NULL, user_salt BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE devices (id UUID PRIMARY KEY, user_id UUID NOT NULL, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ);
CREATE TABLE refresh_tokens (id UUID PRIMARY KEY, device_id UUID NOT NULL, user_id UUID NOT NULL, token_hash TEXT UNIQUE NOT NULL, expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ, revoked BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE manifests (user_id UUID NOT NULL, generation BIGINT NOT NULL, blob BYTEA NOT NULL, signature BYTEA NOT NULL, public_key BYTEA NOT NULL, device_id UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (user_id, generation));
CREATE TABLE objects (user_id UUID NOT NULL, oid TEXT NOT NULL, size BIGINT NOT NULL, storage_ref TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (user_id, oid));
`

// startPostgres launches a throwaway PostgreSQL container and returns its URL.
func startPostgres(ctx context.Context, t *testing.T) string {
	t.Helper()
	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "binpass",
			"POSTGRES_PASSWORD": "binpass",
			"POSTGRES_DB":       "binpass",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req, Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "5432")
	require.NoError(t, err)
	return "postgres://binpass:binpass@" + host + ":" + port.Port() + "/binpass?sslmode=disable"
}

func TestFullSyncCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test requires Docker")
	}
	ctx := context.Background()
	pgURL := startPostgres(ctx, t)

	// Apply schema.
	conn, err := pgx.Connect(ctx, pgURL)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, schema)
	require.NoError(t, err)
	require.NoError(t, conn.Close(ctx))

	// Wire the server components.
	pg, err := postgres.New(ctx, pgURL, 10)
	require.NoError(t, err)
	t.Cleanup(pg.Close)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	issuer := jwt.NewIssuer(priv, time.Hour)
	hasher := argon2.New(argon2.Params{MemoryMiB: 8, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16})

	blobStore, err := blob.NewFS(t.TempDir())
	require.NoError(t, err)
	bus := eventbus.New()

	authUC := usecase.NewAuth(
		persistent.NewUserRepo(pg.Pool), persistent.NewDeviceRepo(pg.Pool),
		persistent.NewTokenRepo(pg.Pool), issuer, hasher, time.Hour)
	vaultUC := usecase.NewVault(
		persistent.NewManifestRepo(pg.Pool), persistent.NewObjectRepo(pg.Pool),
		blobStore, bus, 100*1024*1024)

	interceptor := grpcv1.NewAuthInterceptor(jwt.NewVerifier(pub))
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(interceptor.Unary()),
		grpc.ChainStreamInterceptor(interceptor.Stream()),
	)
	binpassv1.RegisterAuthServer(srv, grpcv1.NewAuthController(authUC))
	binpassv1.RegisterVaultServer(srv, grpcv1.NewVaultController(vaultUC))

	// Serve over an in-memory bufconn.
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }

	// Register the first device via the Auth client.
	authConn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = authConn.Close() })
	authClient := binpassv1.NewAuthClient(authConn)

	reg, err := authClient.Register(ctx, &binpassv1.RegisterRequest{
		Login: "alice", AuthSecret: "c2VjcmV0", DeviceName: "laptop",
	})
	require.NoError(t, err)
	require.NotEmpty(t, reg.GetAccessToken())

	// Device 1: use the Remote client to push an object and commit a manifest.
	rem1, err := remote.DialGRPC("passthrough:///bufnet", staticToken{reg.GetAccessToken()},
		grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rem1.Close() })

	cipher := []byte("this-is-ciphertext")
	require.NoError(t, rem1.PutObject(ctx, "b3:obj1", int64(len(cipher)), bytes.NewReader(cipher)))

	present, err := rem1.HasObjects(ctx, []string{"b3:obj1", "b3:missing"})
	require.NoError(t, err)
	require.True(t, present["b3:obj1"])
	require.False(t, present["b3:missing"])

	gen, err := rem1.CommitManifest(ctx, &remote.SignedManifest{
		Manifest: []byte(`{"gen":1}`), Signature: []byte{1}, PublicKey: []byte{2}, Generation: 1,
	}, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), gen)

	// A stale commit must conflict.
	_, err = rem1.CommitManifest(ctx, &remote.SignedManifest{
		Manifest: []byte(`{"gen":1}`), Signature: []byte{1}, PublicKey: []byte{2}, Generation: 1,
	}, 0)
	require.ErrorIs(t, err, remote.ErrConflict)

	// Device 2: log in as the same owner and pull the manifest and object.
	login, err := authClient.Login(ctx, &binpassv1.LoginRequest{
		Login: "alice", AuthSecret: "c2VjcmV0", DeviceName: "phone",
	})
	require.NoError(t, err)

	rem2, err := remote.DialGRPC("passthrough:///bufnet", staticToken{login.GetAccessToken()},
		grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rem2.Close() })

	m, err := rem2.Manifest(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(1), m.Generation)
	require.Equal(t, []byte(`{"gen":1}`), m.Manifest)

	rc, err := rem2.GetObject(ctx, "b3:obj1")
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	require.Equal(t, cipher, got)
}
