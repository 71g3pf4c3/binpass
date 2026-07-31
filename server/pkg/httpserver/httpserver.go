// Package httpserver runs the binpassd HTTP server that fronts the
// grpc-gateway REST facade, health probes, metrics, and Swagger UI.
package httpserver

import (
	"context"
	"net/http"
	"time"
)

// Server wraps an http.Server with lifecycle helpers.
type Server struct {
	// server is the underlying HTTP server.
	server *http.Server
	// notify carries a fatal serve error to the caller.
	notify chan error
	// shutdownTimeout bounds graceful shutdown.
	shutdownTimeout time.Duration
}

// Config configures the HTTP server.
type Config struct {
	// Addr is the listen address (host:port).
	Addr string
	// Handler is the root HTTP handler.
	Handler http.Handler
	// ReadTimeout bounds request reads.
	ReadTimeout time.Duration
	// WriteTimeout bounds response writes.
	WriteTimeout time.Duration
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
}

// New builds an HTTP server from cfg.
func New(cfg Config) *Server {
	return &Server{
		server: &http.Server{
			Addr:         cfg.Addr,
			Handler:      cfg.Handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
		},
		notify:          make(chan error, 1),
		shutdownTimeout: cfg.ShutdownTimeout,
	}
}

// Start begins serving in a background goroutine.
func (s *Server) Start() {
	go func() {
		s.notify <- s.server.ListenAndServe()
		close(s.notify)
	}()
}

// Notify returns a channel that receives the serve error when it stops.
func (s *Server) Notify() <-chan error { return s.notify }

// Shutdown gracefully stops the server within the configured timeout.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	return s.server.Shutdown(ctx)
}
