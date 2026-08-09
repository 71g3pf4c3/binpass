package v1

import (
	"context"
	"strings"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/71g3pf4c3/binpass/server/pkg/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// sessionKey is the context key for the authenticated session.
type sessionKey struct{}

// publicMethods are RPCs that bypass authentication.
var publicMethods = map[string]bool{
	"/binpass.v1.Auth/Register": true,
	"/binpass.v1.Auth/Login":    true,
	"/binpass.v1.Auth/Refresh":  true,
}

// AuthInterceptor validates access tokens and injects the session.
type AuthInterceptor struct {
	// verifier validates access-token signatures and expiry.
	verifier *jwt.Verifier
}

// NewAuthInterceptor builds an AuthInterceptor.
func NewAuthInterceptor(v *jwt.Verifier) *AuthInterceptor {
	return &AuthInterceptor{verifier: v}
}

// sessionFrom returns the authenticated session from ctx, if any.
func sessionFrom(ctx context.Context) (entity.Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(entity.Session)
	return s, ok
}

// authenticate extracts and verifies the bearer token from ctx metadata.
func (i *AuthInterceptor) authenticate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Unauthenticated, "missing metadata")
	}
	auth := md.Get("authorization")
	if len(auth) == 0 {
		return ctx, status.Error(codes.Unauthenticated, "missing authorization")
	}
	token := strings.TrimPrefix(auth[0], "Bearer ")
	claims, err := i.verifier.Verify(token)
	if err != nil {
		return ctx, status.Error(codes.Unauthenticated, "invalid token")
	}
	sess := entity.Session{UserID: claims.Subject, DeviceID: claims.DeviceID}
	return context.WithValue(ctx, sessionKey{}, sess), nil
}

// Unary returns a unary server interceptor enforcing authentication.
func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		authed, err := i.authenticate(ctx)
		if err != nil {
			return nil, err
		}
		return handler(authed, req)
	}
}

// Stream returns a stream server interceptor enforcing authentication.
func (i *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}
		authed, err := i.authenticate(ss.Context())
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: authed})
	}
}

// wrappedStream overrides Context to carry the authenticated session.
type wrappedStream struct {
	grpc.ServerStream
	// ctx is the authenticated context.
	ctx context.Context
}

// Context returns the authenticated context.
func (w *wrappedStream) Context() context.Context { return w.ctx }
