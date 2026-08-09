// Package grpcserver constructs and runs the binpassd gRPC server.
package grpcserver

import (
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// Server wraps a gRPC server bound to a TCP address.
type Server struct {
	// GRPC is the underlying gRPC server for registering services.
	GRPC *grpc.Server
	// addr is the listen address (host:port).
	addr string
	// notify carries a fatal serve error to the caller.
	notify chan error
}

// New builds a gRPC server listening on addr with the given options.
func New(addr string, opts ...grpc.ServerOption) *Server {
	return &Server{
		GRPC:   grpc.NewServer(opts...),
		addr:   addr,
		notify: make(chan error, 1),
	}
}

// Start begins serving in a background goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("grpcserver: listen: %w", err)
	}
	go func() {
		s.notify <- s.GRPC.Serve(ln)
		close(s.notify)
	}()
	return nil
}

// Notify returns a channel that receives the serve error when it stops.
func (s *Server) Notify() <-chan error { return s.notify }

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() { s.GRPC.GracefulStop() }
