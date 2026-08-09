package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/71g3pf4c3/binpass/server/internal/entity"
	"github.com/71g3pf4c3/binpass/server/pkg/argon2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAuthUC builds an AuthUseCase backed by in-memory fakes and a real (cheap)
// Argon2id hasher so the Login verification path is genuinely exercised.
func newAuthUC() (*AuthUseCase, *fakeTokenRepo) {
	hasher := argon2.New(argon2.Params{MemoryMiB: 8, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16})
	tokens := newFakeTokenRepo()
	uc := NewAuth(newFakeUserRepo(), newFakeDeviceRepo(), tokens, fakeIssuer{}, hasher, time.Hour)
	return uc, tokens
}

func TestRegisterThenLogin(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()

	reg, err := uc.Register(ctx, "alice", "secret", "laptop")
	require.NoError(t, err)
	assert.NotEmpty(t, reg.AccessToken)
	assert.NotEmpty(t, reg.RefreshToken)
	assert.Len(t, reg.UserSalt, 16)

	login, err := uc.Login(ctx, "alice", "secret", "phone")
	require.NoError(t, err)
	assert.NotEmpty(t, login.AccessToken)
	assert.NotEqual(t, reg.DeviceID, login.DeviceID)
}

func TestRegisterDuplicate(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	_, err := uc.Register(ctx, "alice", "secret", "l")
	require.NoError(t, err)
	_, err = uc.Register(ctx, "alice", "secret", "l")
	assert.ErrorIs(t, err, entity.ErrLoginTaken)
}

func TestLoginWrongSecret(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	_, err := uc.Register(ctx, "alice", "secret", "l")
	require.NoError(t, err)
	_, err = uc.Login(ctx, "alice", "wrong", "l")
	assert.ErrorIs(t, err, entity.ErrInvalidCredentials)
}

func TestLoginUnknownUser(t *testing.T) {
	uc, _ := newAuthUC()
	_, err := uc.Login(context.Background(), "ghost", "secret", "l")
	assert.ErrorIs(t, err, entity.ErrInvalidCredentials)
}

func TestRefreshRotation(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	reg, err := uc.Register(ctx, "alice", "secret", "l")
	require.NoError(t, err)

	next, err := uc.Refresh(ctx, reg.RefreshToken)
	require.NoError(t, err)
	assert.NotEqual(t, reg.RefreshToken, next.RefreshToken)
}

func TestRefreshReuseRevokesChain(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	reg, err := uc.Register(ctx, "alice", "secret", "l")
	require.NoError(t, err)

	// First rotation succeeds.
	next, err := uc.Refresh(ctx, reg.RefreshToken)
	require.NoError(t, err)

	// Reusing the original (now rotated) token fails and revokes the chain.
	_, err = uc.Refresh(ctx, reg.RefreshToken)
	assert.ErrorIs(t, err, entity.ErrTokenInvalid)

	// The rotated token is now revoked too.
	_, err = uc.Refresh(ctx, next.RefreshToken)
	assert.ErrorIs(t, err, entity.ErrTokenInvalid)
}

func TestLogout(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	reg, err := uc.Register(ctx, "alice", "secret", "l")
	require.NoError(t, err)

	require.NoError(t, uc.Logout(ctx, reg.RefreshToken))
	_, err = uc.Refresh(ctx, reg.RefreshToken)
	assert.ErrorIs(t, err, entity.ErrTokenInvalid)
}

func TestListAndRevokeDevice(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	reg, err := uc.Register(ctx, "alice", "secret", "laptop")
	require.NoError(t, err)

	user := userIDFromAccess(reg.AccessToken)
	devices, err := uc.ListDevices(ctx, user)
	require.NoError(t, err)
	require.Len(t, devices, 1)

	require.NoError(t, uc.RevokeDevice(ctx, user, reg.DeviceID))
	devices, err = uc.ListDevices(ctx, user)
	require.NoError(t, err)
	assert.True(t, devices[0].Revoked())
}

func TestRevokeForeignDeviceDenied(t *testing.T) {
	uc, _ := newAuthUC()
	ctx := context.Background()
	reg, err := uc.Register(ctx, "alice", "secret", "laptop")
	require.NoError(t, err)
	err = uc.RevokeDevice(ctx, "someone-else", reg.DeviceID)
	assert.ErrorIs(t, err, entity.ErrPermissionDenied)
}

// userIDFromAccess extracts the user ID embedded in the fakeIssuer token
// "access-<userID>-<deviceID>".
func userIDFromAccess(token string) string {
	// token = access-<userID>-<deviceID>; userID is a UUID (contains dashes),
	// so reconstruct by trimming the known prefix and the trailing device ID.
	rest := token[len("access-"):]
	// deviceID is the last UUID; both are UUIDs of equal shape. Split at the
	// boundary: userID is 36 chars.
	return rest[:36]
}
