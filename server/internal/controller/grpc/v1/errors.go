// Package v1 implements the binpassd gRPC controllers (Auth and Vault) and
// the authentication interceptors. Controllers translate protobuf DTOs to and
// from use-case calls and map domain errors to gRPC status codes.
package v1

import (
	"errors"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// toStatus maps a domain error to the appropriate gRPC status.
func toStatus(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, entity.ErrLoginTaken):
		return status.Error(codes.AlreadyExists, "login already taken")
	case errors.Is(err, entity.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, "invalid credentials")
	case errors.Is(err, entity.ErrTokenInvalid):
		return status.Error(codes.Unauthenticated, "token invalid")
	case errors.Is(err, entity.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, entity.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	case errors.Is(err, entity.ErrGenerationMismatch):
		return status.Error(codes.FailedPrecondition, "manifest generation mismatch")
	case errors.Is(err, entity.ErrQuotaExceeded):
		return status.Error(codes.ResourceExhausted, "quota exceeded")
	case errors.Is(err, entity.ErrObjectTooLarge):
		return status.Error(codes.ResourceExhausted, "object too large")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
