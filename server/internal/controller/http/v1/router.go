// Package v1 wires the binpassd HTTP surface: the grpc-gateway REST facade,
// health and readiness probes, Prometheus metrics, and the Swagger UI.
package v1

import (
	"context"
	"embed"
	"io/fs"
	"net/http"

	binpassv1 "github.com/71g3pf4c3/binpass/server/gen/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

//go:embed swagger/*
var swaggerFS embed.FS

// NewRouter builds the root HTTP handler. grpcAddr is the local gRPC address
// the gateway dials to reach the in-process gRPC server.
func NewRouter(ctx context.Context, grpcAddr string) (http.Handler, error) {
	gw := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(func(key string) (string, bool) {
			// Forward Authorization so the gateway propagates bearer tokens.
			if key == "Authorization" {
				return "authorization", true
			}
			return runtime.DefaultHeaderMatcher(key)
		}),
		runtime.WithErrorHandler(errorHandler),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := binpassv1.RegisterAuthHandlerFromEndpoint(ctx, gw, grpcAddr, opts); err != nil {
		return nil, err
	}
	if err := binpassv1.RegisterVaultHandlerFromEndpoint(ctx, gw, grpcAddr, opts); err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", healthHandler)
	mux.Handle("/metrics", promhttp.Handler())

	if sub, err := fs.Sub(swaggerFS, "swagger"); err == nil {
		mux.Handle("/swagger/", http.StripPrefix("/swagger/", http.FileServer(http.FS(sub))))
	}

	mux.Handle("/", gw)
	return mux, nil
}

// healthHandler responds 200 OK for liveness and readiness probes.
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
