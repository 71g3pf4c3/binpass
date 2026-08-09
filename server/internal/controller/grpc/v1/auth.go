package v1

import (
	"context"

	binpassv1 "github.com/71g3pf4c3/binpass/api/gen/v1"
	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/71g3pf4c3/binpass/server/internal/usecase"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuthController adapts the Auth gRPC service to the AuthUseCase.
type AuthController struct {
	binpassv1.UnimplementedAuthServer
	// uc is the authentication use case.
	uc *usecase.AuthUseCase
}

// NewAuthController builds an AuthController.
func NewAuthController(uc *usecase.AuthUseCase) *AuthController {
	return &AuthController{uc: uc}
}

// toTokenPair maps use-case tokens to the wire type.
func toTokenPair(t *usecase.Tokens) *binpassv1.TokenPair {
	return &binpassv1.TokenPair{
		AccessToken:     t.AccessToken,
		RefreshToken:    t.RefreshToken,
		UserSalt:        encodeSalt(t.UserSalt),
		DeviceId:        t.DeviceID,
		AccessExpiresAt: timestamppb.New(t.AccessExpiresAt),
	}
}

// Register handles account creation.
func (c *AuthController) Register(ctx context.Context, req *binpassv1.RegisterRequest) (*binpassv1.TokenPair, error) {
	t, err := c.uc.Register(ctx, req.GetLogin(), req.GetAuthSecret(), req.GetDeviceName())
	if err != nil {
		return nil, toStatus(err)
	}
	return toTokenPair(t), nil
}

// Login handles authentication.
func (c *AuthController) Login(ctx context.Context, req *binpassv1.LoginRequest) (*binpassv1.TokenPair, error) {
	t, err := c.uc.Login(ctx, req.GetLogin(), req.GetAuthSecret(), req.GetDeviceName())
	if err != nil {
		return nil, toStatus(err)
	}
	return toTokenPair(t), nil
}

// Refresh rotates a refresh token.
func (c *AuthController) Refresh(ctx context.Context, req *binpassv1.RefreshRequest) (*binpassv1.TokenPair, error) {
	t, err := c.uc.Refresh(ctx, req.GetRefreshToken())
	if err != nil {
		return nil, toStatus(err)
	}
	return toTokenPair(t), nil
}

// Logout revokes a refresh token.
func (c *AuthController) Logout(ctx context.Context, req *binpassv1.LogoutRequest) (*emptypb.Empty, error) {
	if err := c.uc.Logout(ctx, req.GetRefreshToken()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// ListDevices returns the caller's devices.
func (c *AuthController) ListDevices(ctx context.Context, _ *emptypb.Empty) (*binpassv1.DeviceList, error) {
	sess, ok := sessionFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	devices, err := c.uc.ListDevices(ctx, sess.UserID)
	if err != nil {
		return nil, toStatus(err)
	}
	out := &binpassv1.DeviceList{Devices: make([]*binpassv1.Device, 0, len(devices))}
	for _, d := range devices {
		out.Devices = append(out.Devices, toDevice(d))
	}
	return out, nil
}

// RevokeDevice revokes one of the caller's devices.
func (c *AuthController) RevokeDevice(ctx context.Context, req *binpassv1.RevokeDeviceRequest) (*emptypb.Empty, error) {
	sess, ok := sessionFrom(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	if err := c.uc.RevokeDevice(ctx, sess.UserID, req.GetDeviceId()); err != nil {
		return nil, toStatus(err)
	}
	return &emptypb.Empty{}, nil
}

// toDevice maps a device entity to the wire type.
func toDevice(d entity.Device) *binpassv1.Device {
	return &binpassv1.Device{
		Id:         d.ID,
		Name:       d.Name,
		CreatedAt:  timestamppb.New(d.CreatedAt),
		LastSeenAt: timestamppb.New(d.LastSeenAt),
		Revoked:    d.Revoked(),
	}
}
