// Package app wires binpassd together: configuration, migrations, database,
// repositories, use cases, gRPC and HTTP controllers, and graceful shutdown.
// It is the only package that depends on every layer; nothing depends on it.
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	binpassv1 "github.com/71g3pf4c3/binpass/api/gen/v1"
	"github.com/71g3pf4c3/binpass/server/config"
	grpcv1 "github.com/71g3pf4c3/binpass/server/internal/controller/grpc/v1"
	httpv1 "github.com/71g3pf4c3/binpass/server/internal/controller/http/v1"
	"github.com/71g3pf4c3/binpass/server/internal/usecase"
	"github.com/71g3pf4c3/binpass/server/internal/usecase/repo/blob"
	"github.com/71g3pf4c3/binpass/server/internal/usecase/repo/eventbus"
	"github.com/71g3pf4c3/binpass/server/internal/usecase/repo/persistent"
	"github.com/71g3pf4c3/binpass/server/pkg/argon2"
	"github.com/71g3pf4c3/binpass/server/pkg/grpcserver"
	"github.com/71g3pf4c3/binpass/server/pkg/httpserver"
	"github.com/71g3pf4c3/binpass/server/pkg/jwt"
	"github.com/71g3pf4c3/binpass/server/pkg/logger"
	"github.com/71g3pf4c3/binpass/server/pkg/postgres"
	"google.golang.org/grpc"
)

// Run assembles and starts the server, blocking until a shutdown signal or a
// fatal server error.
func Run(cfg *config.Config) error {
	log := logger.New(cfg.Log.Level, cfg.Log.Format)
	ctx := context.Background()

	if err := runMigrations(cfg.PG.URL); err != nil {
		return fmt.Errorf("app: migrations: %w", err)
	}
	log.Info("migrations applied")

	pg, err := postgres.New(ctx, cfg.PG.URL, cfg.PG.PoolMax)
	if err != nil {
		return fmt.Errorf("app: postgres: %w", err)
	}
	defer pg.Close()

	priv, pub, err := loadOrGenerateKey(cfg.Auth.JWTPrivateKey, log.Warn)
	if err != nil {
		return err
	}

	// Infrastructure.
	blobStore, err := blob.NewFS(cfg.Blob.FSPath)
	if err != nil {
		return fmt.Errorf("app: blob: %w", err)
	}
	bus := eventbus.New()
	hasher := argon2.New(argon2.Params{
		MemoryMiB: cfg.Auth.Argon2.MemoryMiB,
		Time:      cfg.Auth.Argon2.Time,
		Threads:   cfg.Auth.Argon2.Threads,
		KeyLen:    32,
		SaltLen:   16,
	})
	issuer := jwt.NewIssuer(priv, cfg.Auth.AccessTTL)

	// Repositories.
	users := persistent.NewUserRepo(pg.Pool)
	devices := persistent.NewDeviceRepo(pg.Pool)
	tokens := persistent.NewTokenRepo(pg.Pool)
	manifests := persistent.NewManifestRepo(pg.Pool)
	objects := persistent.NewObjectRepo(pg.Pool)

	// Use cases.
	authUC := usecase.NewAuth(users, devices, tokens, issuer, hasher, cfg.Auth.RefreshTTL)
	vaultUC := usecase.NewVault(manifests, objects, blobStore, bus, cfg.Limits.MaxObjectSize)

	// gRPC server with auth interceptors.
	interceptor := grpcv1.NewAuthInterceptor(jwt.NewVerifier(pub))
	maxRecv := cfg.GRPC.MaxRecvMiB
	if maxRecv <= 0 {
		maxRecv = 8
	}
	grpcSrv := grpcserver.New(":"+cfg.GRPC.Port,
		grpc.ChainUnaryInterceptor(interceptor.Unary()),
		grpc.ChainStreamInterceptor(interceptor.Stream()),
		grpc.MaxRecvMsgSize(maxRecv*1024*1024),
	)
	binpassv1.RegisterAuthServer(grpcSrv.GRPC, grpcv1.NewAuthController(authUC))
	binpassv1.RegisterVaultServer(grpcSrv.GRPC, grpcv1.NewVaultController(vaultUC))
	if err := grpcSrv.Start(); err != nil {
		return fmt.Errorf("app: grpc start: %w", err)
	}
	log.Info("grpc listening", "port", cfg.GRPC.Port)

	// HTTP server (gateway + health/metrics/swagger).
	router, err := httpv1.NewRouter(ctx, "127.0.0.1:"+cfg.GRPC.Port)
	if err != nil {
		return fmt.Errorf("app: http router: %w", err)
	}
	httpSrv := httpserver.New(httpserver.Config{
		Addr:            ":" + cfg.HTTP.Port,
		Handler:         router,
		ReadTimeout:     cfg.HTTP.ReadTimeout,
		WriteTimeout:    cfg.HTTP.WriteTimeout,
		ShutdownTimeout: cfg.HTTP.ShutdownTimeout,
	})
	httpSrv.Start()
	log.Info("http listening", "port", cfg.HTTP.Port)

	// Wait for a signal or a fatal server error.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case s := <-stop:
		log.Info("shutdown signal", "signal", s.String())
	case err := <-grpcSrv.Notify():
		log.Error("grpc server stopped", "error", err)
	case err := <-httpSrv.Notify():
		log.Error("http server stopped", "error", err)
	}

	// Graceful shutdown.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = shutdownCtx
	if err := httpSrv.Shutdown(); err != nil {
		log.Error("http shutdown", "error", err)
	}
	grpcSrv.Shutdown()
	log.Info("stopped")
	return nil
}

// loadOrGenerateKey derives an Ed25519 keypair from a base64 seed, or
// generates an ephemeral one (dev only) with a warning.
func loadOrGenerateKey(seedB64 string, warn func(string, ...any)) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if seedB64 == "" {
		warn("no BINPASSD_JWT_PRIVATE_KEY set; generating an ephemeral key (tokens will not survive restart)")
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, nil, fmt.Errorf("app: gen key: %w", err)
		}
		return priv, pub, nil
	}
	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		return nil, nil, fmt.Errorf("app: decode jwt key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("app: jwt key must be a %d-byte seed", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey), nil
}
